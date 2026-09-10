<script>
  import { NAV_ITEMS, ROUTES } from '../../lib/constants.js';
  import { navigate, isActive } from '../../lib/router.js';
  import { nodeState } from '../../lib/stores.js';

  /**
   * @param {string} route - Current route path.
   */
  let { route = '/' } = $props();

  let pendingCount = $derived(nodeState.joinRequests.filter((r) => r.status === 'pending').length);

  // Bottom nav shows a subset of nav items (mobile space is limited)
  const bottomNavItems = [
    { route: ROUTES.DASHBOARD, label: 'Home', icon: 'grid' },
    { route: ROUTES.MY_NODE, label: 'Node', icon: 'server' },
    { route: ROUTES.ACCOUNTS, label: 'Accounts', icon: 'wallet' },
    { route: ROUTES.ACTIVITY, label: 'Activity', icon: 'list' },
    { route: ROUTES.SETTINGS, label: 'More', icon: 'settings' },
  ];

  const icons = {
    grid: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
    server: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/></svg>',
    wallet: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 10h20"/></svg>',
    list: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
    settings: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>',
  };

  function handleNav(routePath) {
    navigate(routePath);
  }
</script>

<nav class="mobile-nav" aria-label="Main navigation">
  {#each bottomNavItems as item}
    {@const active = isActive(item.route, route)}
    <button
      type="button"
      class="mobile-nav-item"
      class:mobile-nav-item--active={active}
      onclick={() => handleNav(item.route)}
      aria-current={active ? 'page' : undefined}
    >
      <span class="mobile-nav-icon">{@html icons[item.icon]}</span>
      <span class="mobile-nav-label">{item.label}</span>
      {#if item.route === ROUTES.JOINS && pendingCount > 0}
        <span class="mobile-nav-badge">{pendingCount}</span>
      {/if}
    </button>
  {/each}
</nav>

<style>
  .mobile-nav {
    display: none;
  }

  @media (max-width: 767px) {
    .mobile-nav {
      display: flex;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 100;
      height: var(--mobile-nav-height);
      background: var(--bg-raised);
      border-top: 1px solid var(--border);
      align-items: center;
      justify-content: space-around;
      padding: 0 var(--sp-2);
    }
  }

  .mobile-nav-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: var(--sp-1) var(--sp-2);
    border: none;
    background: transparent;
    color: var(--muted);
    font: inherit;
    font-size: 10px;
    cursor: pointer;
    position: relative;
    border-radius: var(--radius-md);
    min-width: 48px;
    transition: color var(--duration-fast) var(--ease);
  }
  .mobile-nav-item:hover {
    color: var(--fg);
  }
  .mobile-nav-item--active {
    color: var(--accent);
  }
  .mobile-nav-icon {
    display: flex;
    align-items: center;
  }
  .mobile-nav-label {
    line-height: 1;
  }
  .mobile-nav-badge {
    position: absolute;
    top: 0;
    right: 4px;
    min-width: 16px;
    height: 16px;
    border-radius: 8px;
    background: var(--warn);
    color: var(--bg);
    font-size: 10px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0 4px;
  }
</style>
