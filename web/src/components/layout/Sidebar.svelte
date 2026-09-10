<script>
  import { NAV_ITEMS, ROUTES } from '../../lib/constants.js';
  import { navigate, isActive } from '../../lib/router.js';
  import { clientState, nodeState } from '../../lib/stores.js';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';

  /**
   * @param {string} route - Current route path.
   */
  let { route = '/' } = $props();

  let pendingCount = $derived(nodeState.joinRequests.filter((r) => r.status === 'pending').length);

  const icons = {
    grid: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
    server: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/></svg>',
    wallet: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 10h20"/></svg>',
    list: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
    'user-plus': '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6M23 11h-6"/></svg>',
    user: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    settings: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>',
  };

  function handleNav(routePath) {
    navigate(routePath);
  }
</script>

<aside class="sidebar">
  <div class="sidebar-header">
    <span class="logo">Cawala</span>
  </div>

  <nav class="sidebar-nav" aria-label="Main navigation">
    {#each NAV_ITEMS as item}
      {@const active = isActive(item.route, route)}
      <button
        type="button"
        class="nav-item"
        class:nav-item--active={active}
        onclick={() => handleNav(item.route)}
        aria-current={active ? 'page' : undefined}
      >
        <span class="nav-icon">{@html icons[item.icon]}</span>
        <span class="nav-label">{item.label}</span>
        {#if item.route === ROUTES.JOINS && pendingCount > 0}
          <Badge variant="warn" label={String(pendingCount)} />
        {/if}
      </button>
    {/each}
  </nav>

  <div class="sidebar-footer">
    <ConnectionIndicator status={clientState.connectionStatus} />
    {#if clientState.endpointId}
      <div class="sidebar-endpoint">
        <EndpointId id={clientState.endpointId} truncate={true} />
      </div>
    {/if}
    <span class="version">M4 · mock mode</span>
  </div>
</aside>

<style>
  .sidebar {
    width: var(--sidebar-width);
    height: 100vh;
    height: 100dvh;
    position: fixed;
    left: 0;
    top: 0;
    z-index: 100;
    display: flex;
    flex-direction: column;
    background: var(--bg-raised);
    border-right: 1px solid var(--border);
  }
  .sidebar-header {
    padding: var(--sp-5) var(--sp-5) var(--sp-4);
    border-bottom: 1px solid var(--border);
  }
  .logo {
    font-size: var(--text-lg);
    font-weight: 700;
    color: var(--fg);
    letter-spacing: -0.02em;
  }
  .sidebar-nav {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: var(--sp-3) var(--sp-3);
    overflow-y: auto;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--muted);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
    text-align: left;
    transition: background var(--duration-fast) var(--ease), color var(--duration-fast) var(--ease);
    border-left: 2px solid transparent;
    margin-left: -2px;
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--fg);
  }
  .nav-item--active {
    background: var(--bg-hover);
    color: var(--fg);
    border-left-color: var(--accent);
  }
  .nav-icon {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }
  .nav-label {
    flex: 1;
  }
  .sidebar-footer {
    padding: var(--sp-4) var(--sp-5);
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .sidebar-endpoint {
    margin-top: var(--sp-1);
  }
  .version {
    font-size: var(--text-xs);
    color: var(--border);
    margin-top: var(--sp-1);
  }

  /* Hide on mobile */
  @media (max-width: 767px) {
    .sidebar {
      display: none;
    }
  }
</style>
