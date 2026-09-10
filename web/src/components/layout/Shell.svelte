<script>
  import { currentRoute } from '../../lib/router.js';
  import { clientState, uiState } from '../../lib/stores.js';
  import Sidebar from './Sidebar.svelte';
  import TopBar from './TopBar.svelte';
  import MobileNav from './MobileNav.svelte';
  import Toast from '../shared/Toast.svelte';

  let { children } = $props();

  let route = $derived(currentRoute());
</script>

<!-- Skip link -->
<a href="#main-content" class="skip-link">Skip to main content</a>

<div class="shell">
  <Sidebar {route} />
  <div class="shell-main">
    <TopBar {route} />
    <main id="main-content" class="shell-content">
      {@render children()}
    </main>
  </div>
  <MobileNav {route} />
</div>

<Toast />

<style>
  .shell {
    display: flex;
    min-height: 100vh;
    min-height: 100dvh;
  }
  .shell-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .shell-content {
    flex: 1;
    padding: var(--sp-6);
    max-width: 960px;
    width: 100%;
    margin: 0 auto;
  }

  /* Mobile: no sidebar, bottom nav */
  @media (max-width: 767px) {
    .shell-content {
      padding: var(--sp-4);
      padding-bottom: calc(var(--mobile-nav-height) + var(--sp-4));
    }
  }
</style>
