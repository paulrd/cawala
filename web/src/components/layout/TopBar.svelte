<script>
  import { NAV_ITEMS, ROUTES } from '../../lib/constants.js';
  import { isActive } from '../../lib/router.js';
  import { clientState } from '../../lib/stores.js';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';

  /**
   * @param {string} route - Current route path.
   */
  let { route = '/' } = $props();

  let pageTitle = $derived.by(() => {
    const item = NAV_ITEMS.find((n) => isActive(n.route, route, n.route === '/'));
    return item?.label ?? 'Cawala';
  });
</script>

<header class="topbar">
  <div class="topbar-left">
    <h1 class="topbar-title">{pageTitle}</h1>
  </div>
  <div class="topbar-right">
    <ConnectionIndicator status={clientState.connectionStatus} />
  </div>
</header>

<style>
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-4) var(--sp-6);
    border-bottom: 1px solid var(--border);
    min-height: var(--topbar-height);
    background: var(--bg);
  }
  .topbar-title {
    font-size: var(--text-xl);
    font-weight: 700;
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
  }

  @media (max-width: 767px) {
    .topbar {
      padding: var(--sp-3) var(--sp-4);
    }
    .topbar-title {
      font-size: var(--text-lg);
    }
  }
</style>
