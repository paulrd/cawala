<script>
  import { administeredNode, adminLock, targetEpoch } from '../../lib/stores.svelte.js';
  import { getAdminTargets, discoverAdminTargets, stepAdminTarget, adminTargetBounds } from '../../lib/api.js';
  import { buildAncestorPath, depthLabel, shortId, statusBadge } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';
  import Badge from '../shared/Badge.svelte';
  import AdminUnlockDialog from './AdminUnlockDialog.svelte';

  /**
   * AdminTargetSwitcher — step up and down the ancestor chain (R7).
   *
   * There is no dropdown anymore: admin mode points at exactly one node on the
   * path from this browser to the root, and this control moves that pointer.
   * Both ends of the chain disable their arrow, the current position is drawn
   * as a breadcrumb with one highlighted crumb, and every crumb carries the
   * address the node last reported.
   *
   * While admin mode is locked the arrows are disabled and the control offers
   * the unlock gate instead of a target.
   *
   * @param {'bar'|'page'} [variant='bar']
   */
  let { variant = 'bar' } = $props();

  let view = administeredNode;
  let locked = $derived(!adminLock.unlocked);
  let busy = $state(false);
  let unlockOpen = $state(false);

  // The target list lives in the api layer as plain module state; `targetEpoch`
  // is what the api bumps when it changes, so the crumbs re-render here.
  let targets = $derived.by(() => {
    void targetEpoch.value;
    return getAdminTargets();
  });

  let bounds = $derived.by(() => {
    void targetEpoch.value;
    return adminTargetBounds();
  });

  let crumbs = $derived(buildAncestorPath(targets, bounds?.current ?? null));
  let maxDepth = $derived(crumbs.length ? crumbs[crumbs.length - 1].depth : 0);
  let status = $derived(statusBadge(view.status));

  let canUp = $derived(!locked && bounds != null && bounds.current != null && bounds.current < bounds.max);
  let canDown = $derived(!locked && bounds != null && bounds.current != null && bounds.current > bounds.min);

  async function step(delta) {
    if (busy) return;
    busy = true;
    try {
      stepAdminTarget(delta);
    } finally {
      busy = false;
    }
  }

  async function jump(depth) {
    if (locked || depth == null) return;
    stepAdminTarget(depth - (bounds?.current ?? depth));
  }

  async function rediscover() {
    if (busy) return;
    busy = true;
    try {
      await discoverAdminTargets();
    } catch {
      /* discoverAdminTargets records its own outcome; the view stays honest */
    } finally {
      busy = false;
    }
  }
</script>

{#if locked}
  <div class="switcher switcher--{variant} switcher--locked">
    <span class="locked-copy text-xs">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
      Admin mode locked
    </span>
    <button type="button" class="step step--unlock" onclick={() => (unlockOpen = true)}>
      Unlock
    </button>
  </div>
{:else if targets.length === 0}
  <div class="switcher switcher--{variant} switcher--empty">
    <span class="empty-copy text-xs">
      No ancestor found — this browser has no parent node to administer.
    </span>
    <button type="button" class="step" onclick={rediscover} disabled={busy}>
      {busy ? 'Checking…' : 'Retry'}
    </button>
  </div>
{:else}
  <div class="switcher switcher--{variant}" role="group" aria-label="Admin target">
    <div class="steps">
      <button
        type="button"
        class="step"
        class:step--wide={variant === 'page'}
        disabled={!canUp || busy}
        onclick={() => step(1)}
        title="Step up toward the root"
        aria-label="Administer the node one level up"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <polyline points="18 15 12 9 6 15" />
        </svg>
        {#if variant === 'page'}<span>Up</span>{/if}
      </button>
      <button
        type="button"
        class="step"
        class:step--wide={variant === 'page'}
        disabled={!canDown || busy}
        onclick={() => step(-1)}
        title="Step down toward this browser"
        aria-label="Administer the node one level down"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <polyline points="6 9 12 15 18 9" />
        </svg>
        {#if variant === 'page'}<span>Down</span>{/if}
      </button>
    </div>

    <div class="readout">
      {#if variant === 'page'}
        <div class="readout-head">
          <span class="readout-label text-xs">Administering</span>
          <Badge variant={kindBadgeVariant(view.kind)} label={kindLabel(view.kind)} />
          <Badge variant={status.variant} label={status.label} />
        </div>
      {/if}

      <div class="crumbs" aria-label="Ancestor path">
        <span class="crumb crumb--self" title="This browser">
          <span class="crumb-dot" aria-hidden="true"></span>
          This browser
        </span>
        {#each crumbs as crumb (crumb.depth)}
          <span class="crumb-sep" aria-hidden="true">→</span>
          <button
            type="button"
            class="crumb"
            class:crumb--current={crumb.current}
            onclick={() => jump(crumb.depth)}
            aria-current={crumb.current ? 'true' : undefined}
            title="{depthLabel(crumb.depth, maxDepth)} · node {crumb.node}"
          >
            <span class="crumb-label">{crumb.label}</span>
            {#if crumb.address}
              <span class="crumb-addr mono">{crumb.address}</span>
            {/if}
            {#if crumb.current}
              <span class="crumb-you text-xs">current</span>
            {/if}
          </button>
        {/each}
      </div>

      {#if variant === 'page'}
        <p class="readout-foot text-xs">
          {#if view.address}
            Address <code class="mono">{view.address}</code> ·
          {/if}
          Node <code class="mono">{shortId(view.nodeId)}</code> ·
          {depthLabel(bounds.current ?? 1, maxDepth).toLowerCase()} of {crumbs.length}
          {bounds.count > 1 ? 'levels' : 'level'} above this browser
        </p>
      {/if}
    </div>
  </div>
{/if}

<AdminUnlockDialog open={unlockOpen} onCancel={() => (unlockOpen = false)} onUnlocked={() => (unlockOpen = false)} />

<style>
  .switcher {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    min-width: 0;
  }
  .switcher--page {
    align-items: flex-start;
    gap: var(--sp-4);
    padding: var(--sp-4);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    flex-wrap: wrap;
  }
  .switcher--locked,
  .switcher--empty {
    padding: var(--sp-2) var(--sp-3);
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
  }
  .locked-copy {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    color: var(--muted);
    white-space: nowrap;
  }
  .empty-copy {
    color: var(--muted);
  }

  .steps {
    display: flex;
    gap: var(--sp-1);
    flex-shrink: 0;
  }
  .step {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-2);
    min-width: 30px;
    height: 30px;
    padding: 0 var(--sp-2);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    transition:
      background var(--duration-fast) var(--ease),
      border-color var(--duration-fast) var(--ease),
      color var(--duration-fast) var(--ease);
  }
  .step--wide {
    height: 34px;
    padding: 0 var(--sp-3);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: var(--text-xs);
  }
  .step:hover:not(:disabled) {
    border-color: var(--accent);
    color: var(--accent);
  }
  .step:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .step--unlock {
    color: var(--accent);
    border-color: var(--accent);
    flex-shrink: 0;
  }

  .readout {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    min-width: 0;
    flex: 1;
  }
  .readout-head {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .readout-label {
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .readout-foot {
    color: var(--muted);
  }
  .readout-foot code {
    font-family: var(--mono);
  }

  .crumbs {
    display: flex;
    align-items: center;
    gap: var(--sp-1);
    flex-wrap: wrap;
    min-width: 0;
  }
  .crumb-sep {
    color: var(--muted);
    font-size: var(--text-xs);
  }
  .crumb {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 3px var(--sp-2);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 999px;
    font: inherit;
    font-size: var(--text-xs);
    color: var(--muted);
    white-space: nowrap;
  }
  button.crumb {
    cursor: pointer;
    transition:
      border-color var(--duration-fast) var(--ease),
      color var(--duration-fast) var(--ease);
  }
  button.crumb:hover:not(:disabled) {
    color: var(--fg);
    border-color: var(--accent);
  }
  .crumb--self {
    border-style: dashed;
  }
  .crumb-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--muted);
    flex-shrink: 0;
  }
  .crumb--current {
    border-color: var(--accent);
    background: var(--accent-dim);
    color: var(--fg);
    font-weight: 600;
  }
  .crumb-label {
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 10px;
  }
  .crumb-addr {
    font-family: var(--mono);
    color: var(--muted);
  }
  .crumb--current .crumb-addr {
    color: var(--fg);
  }
  .crumb-you {
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 9px;
  }

  @media (max-width: 767px) {
    .switcher--bar {
      flex-wrap: wrap;
    }
  }
</style>
