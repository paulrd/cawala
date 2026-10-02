<script>
  /**
   * ConnectionIndicator — dot + label showing parent-node attachment status.
   *
   * Every state differs by colour *and* shape, so the four states stay
   * readable in greyscale / for colour-blind users without adding an icon:
   *   connected    → solid dot
   *   connecting   → solid dot + breathing halo (reads as "in progress")
   *   disconnected → hollow ring (nothing attached)
   *   mock         → dimmed square (a different category: not a live link)
   *
   * @param {string} status - 'connected' | 'connecting' | 'disconnected' | 'mock'
   */
  let { status = 'disconnected' } = $props();

  const labels = {
    connected: 'Connected',
    connecting: 'Connecting\u2026',
    disconnected: 'Disconnected',
    mock: 'Mock',
  };

  /** Hover copy, one per state — mirrors `_deriveConnectionStatus` in api.js. */
  const tooltips = {
    connected: 'Live \u2014 attached to a parent node',
    connecting: 'Join in progress \u2014 waiting for parent approval',
    disconnected: 'Live \u2014 no parent attached (not joined, or parent unreachable)',
    mock: 'Mock mode \u2014 simulated data, no live network connection',
  };

  const variants = {
    connected: 'ok',
    connecting: 'warn',
    disconnected: 'danger',
    mock: 'muted',
  };
</script>

<span class="connection-indicator" title={tooltips[status]}>
  <span class="dot dot--{variants[status]}" class:pulse={status === 'connecting'} aria-hidden="true"></span>
  <span class="sr-only">Connection status: </span>
  <span class="label label--{variants[status]}">{labels[status]}</span>
</span>

<style>
  .connection-indicator {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    font-size: var(--text-xs);
    line-height: var(--leading-tight);
  }
  .dot {
    position: relative;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot--ok { background: var(--ok); }
  .dot--warn { background: var(--warn); }
  /* Hollow ring: "nothing attached" — legible without colour. */
  .dot--danger {
    background: transparent;
    border: 2px solid var(--danger);
  }
  /* Dimmed square: neutral, not an error, and clearly not a live link. */
  .dot--muted {
    background: var(--muted);
    border-radius: 2px;
    opacity: 0.75;
  }

  /* Connecting: a halo ring breathes around the dot = "in progress".
     The ring is always present, so the state keeps its shape cue even
     in greyscale or when motion is off. */
  .pulse::after {
    content: '';
    position: absolute;
    inset: -3px;
    border: 2px solid var(--warn);
    border-radius: 50%;
    opacity: 0.4;
    animation: halo-pulse 1.5s ease-in-out infinite;
  }
  @keyframes halo-pulse {
    0%, 100% { opacity: 0.2; }
    50% { opacity: 0.75; }
  }
  /* Static halo, no motion — same pattern as `.skeleton` in app.css. */
  @media (prefers-reduced-motion: reduce) {
    .pulse::after {
      animation: none;
      opacity: 0.4;
    }
  }

  .label {
    white-space: nowrap;
    font-weight: 500;
  }
  .label--ok { color: var(--ok); }
  .label--warn { color: var(--warn); }
  .label--danger { color: var(--danger); }
  .label--muted { color: var(--muted); }
</style>
