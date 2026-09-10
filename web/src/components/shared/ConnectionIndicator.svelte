<script>
  /**
   * ConnectionIndicator — dot + label showing relay connection status.
   * @param {string} status - 'connected' | 'connecting' | 'disconnected'
   */
  let { status = 'disconnected' } = $props();

  const labels = {
    connected: 'Connected',
    connecting: 'Connecting\u2026',
    disconnected: 'Disconnected',
  };

  const variants = {
    connected: 'ok',
    connecting: 'warn',
    disconnected: 'danger',
  };
</script>

<span class="connection-indicator" title={labels[status]}>
  <span class="dot dot--{variants[status]}" class:pulse={status === 'connecting'}></span>
  <span class="label">{labels[status]}</span>
</span>

<style>
  .connection-indicator {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    font-size: var(--text-xs);
    color: var(--muted);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot--ok { background: var(--ok); }
  .dot--warn { background: var(--warn); }
  .dot--danger { background: var(--danger); }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  .pulse {
    animation: pulse 1.5s ease-in-out infinite;
  }
  .label {
    white-space: nowrap;
  }
</style>
