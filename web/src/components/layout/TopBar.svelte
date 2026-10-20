<script>
  import { NAV_ITEMS, PAGE_TITLES, ROUTES } from '../../lib/constants.js';
  import { activeNavRoute, navigate } from '../../lib/router.svelte.js';
  import { clientState, ledgerState } from '../../lib/stores.svelte.js';
  import { formatBalance } from '../../lib/utils.js';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';

  /**
   * @param {string} route - Current route path.
   */
  let { route = '/' } = $props();

  let pageTitle = $derived.by(() => {
    // Non-nav routes get their own title; nav routes stay exactly as before.
    if (PAGE_TITLES[route]) return PAGE_TITLES[route];
    const active = activeNavRoute(NAV_ITEMS.map((n) => n.route), route);
    const item = NAV_ITEMS.find((n) => n.route === active);
    return item?.label ?? 'Cawala';
  });

  let onAccountPage = $derived(route === ROUTES.MY_ACCOUNT);
  // Only a verified balance is shown, never a placeholder.
  let balanceText = $derived(
    ledgerState.balance == null
      ? null
      : formatBalance(ledgerState.balance, { showSign: false }),
  );
  // The button is icon-only on mobile, so the name and balance live here too.
  let accountLabel = $derived(
    balanceText == null ? 'My Account' : `My Account, balance ${balanceText}`,
  );
</script>

<header class="topbar">
  <div class="topbar-left">
    <h1 class="topbar-title">{pageTitle}</h1>
  </div>
  <div class="topbar-right">
    <button
      type="button"
      class="account-btn"
      class:account-btn--active={onAccountPage}
      onclick={() => navigate(ROUTES.MY_ACCOUNT)}
      aria-label={accountLabel}
      aria-current={onAccountPage ? 'page' : undefined}
    >
      <span class="account-icon" aria-hidden="true">
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
      </span>
      <span class="account-label">My Account</span>
      {#if balanceText != null}
        <span class="account-sep" aria-hidden="true">&middot;</span>
        <span class="account-balance">{balanceText}</span>
      {/if}
    </button>
    <ConnectionIndicator status={clientState.connectionStatus} />
  </div>
</header>

<style>
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    padding: var(--sp-4) var(--sp-6);
    border-bottom: 1px solid var(--border);
    min-height: var(--topbar-height);
    background: var(--bg);
  }
  .topbar-left {
    min-width: 0;
  }
  .topbar-title {
    font-size: var(--text-xl);
    font-weight: 700;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    flex-shrink: 0;
  }

  /* Same active treatment as the sidebar nav: raised background, full-strength
     text, and an accent bar — laid flat for the horizontal bar. */
  .account-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-1) var(--sp-3);
    /* Sits inside the 56px bar without growing it past the title's line box. */
    min-height: 32px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    color: var(--muted);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
    transition:
      background var(--duration-fast) var(--ease),
      color var(--duration-fast) var(--ease);
  }
  .account-btn:hover {
    background: var(--bg-hover);
    color: var(--fg);
  }
  .account-btn--active {
    background: var(--bg-hover);
    color: var(--fg);
    box-shadow: inset 0 -2px 0 var(--accent);
  }
  .account-icon {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }
  .account-sep {
    color: var(--muted);
  }
  .account-balance {
    font-family: var(--mono);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    color: var(--fg);
  }

  @media (max-width: 767px) {
    .topbar {
      padding: var(--sp-2) var(--sp-4);
    }
    .topbar-title {
      font-size: var(--text-lg);
    }
    /* Icon-only below the mobile breakpoint, with the balance kept in view:
       the top bar has no room for the full label next to the connection
       indicator, and the number is the part worth glancing at. */
    .account-btn {
      min-width: 44px;
      min-height: 44px;
      justify-content: center;
      padding: var(--sp-2);
    }
    .account-label,
    .account-sep {
      display: none;
    }
  }
</style>
