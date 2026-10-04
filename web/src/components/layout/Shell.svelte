<script>
  import { currentRoute } from '../../lib/router.svelte.js';
  import Sidebar from './Sidebar.svelte';
  import TopBar from './TopBar.svelte';
  import NodeContextBar from './NodeContextBar.svelte';
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
    <!-- One header for every route: page title + the ancestor target
         switcher/context bar, so the current target is always visible. -->
    <div class="shell-header">
      <TopBar {route} />
      <NodeContextBar />
    </div>
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
  /* The sidebar is fixed, so the column it sits beside is offset here —
     including the sticky header, which must never paint over the nav. */
  @media (min-width: 768px) {
    .shell-main {
      padding-left: var(--sidebar-width);
    }
  }
  .shell-header {
    position: sticky;
    top: 0;
    z-index: 150;
    background: var(--bg);
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
