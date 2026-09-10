<script>
  import { onMount } from 'svelte';
  import { initRouter, currentRoute } from './lib/router.js';
  import { clientState } from './lib/stores.js';
  import { initApi, spawnClient, isMockMode } from './lib/api.js';
  import Shell from './components/layout/Shell.svelte';
  import Dashboard from './components/dashboard/Dashboard.svelte';
  import NodePage from './components/node/NodePage.svelte';
  import AccountsPage from './components/accounts/AccountsPage.svelte';
  import ActivityPage from './components/activity/ActivityPage.svelte';
  import JoinsPage from './components/joins/JoinsPage.svelte';
  import MyAccountPage from './components/account/MyAccountPage.svelte';
  import SettingsPage from './components/settings/SettingsPage.svelte';
  import JoinFlowPage from './components/join-flow/JoinFlowPage.svelte';

  let ready = $state(false);
  let initError = $state(null);

  // Initialize on mount
  onMount(async () => {
    initRouter();
    try {
      await initApi();
      const result = await spawnClient();
      clientState.status = 'ready';
      clientState.endpointId = result.endpointId;
      clientState.address = result.address;
      clientState.connectionStatus = 'connected';
    } catch (err) {
      clientState.status = 'error';
      clientState.error = err.message;
      initError = err.message;
      console.error('[App] init failed:', err);
    }
    ready = true;
  });

  let route = $derived(currentRoute());
</script>

{#if !ready}
  <!-- Initial loading state -->
  <div class="app-loading">
    <div class="loading-content">
      <span class="logo">Cawala</span>
      <div class="loading-bar"></div>
      <p class="muted text-sm">Starting client…</p>
    </div>
  </div>
{:else if initError}
  <!-- Init error — show minimal shell with error -->
  <div class="app-loading">
    <div class="loading-content">
      <span class="logo">Cawala</span>
      <p class="error-text">Failed to start: {initError}</p>
      <p class="muted text-sm">Check your network connection and try refreshing.</p>
    </div>
  </div>
{:else}
  <Shell>
    {#if route === '/' || route === ''}
      <Dashboard />
    {:else if route === '/node' || route.startsWith('/node/')}
      <NodePage />
    {:else if route === '/accounts'}
      <AccountsPage />
    {:else if route === '/activity'}
      <ActivityPage />
    {:else if route === '/node/joins'}
      <JoinsPage />
    {:else if route === '/account'}
      <MyAccountPage />
    {:else if route === '/settings'}
      <SettingsPage />
    {:else if route === '/join'}
      <JoinFlowPage />
    {:else}
      <!-- 404 -->
      <div class="not-found">
        <h2>Page not found</h2>
        <p class="muted">The page <code>{route}</code> doesn't exist.</p>
      </div>
    {/if}
  </Shell>
{/if}

<style>
  .app-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    min-height: 100dvh;
    background: var(--bg);
  }
  .loading-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-4);
  }
  .logo {
    font-size: var(--text-2xl);
    font-weight: 700;
    color: var(--fg);
    letter-spacing: -0.02em;
  }
  .loading-bar {
    width: 120px;
    height: 2px;
    background: var(--border);
    border-radius: 1px;
    overflow: hidden;
    position: relative;
  }
  .loading-bar::after {
    content: '';
    position: absolute;
    top: 0;
    left: -40%;
    width: 40%;
    height: 100%;
    background: var(--accent);
    border-radius: 1px;
    animation: loading-slide 1.2s ease-in-out infinite;
  }
  @keyframes loading-slide {
    0% { left: -40%; }
    100% { left: 100%; }
  }
  .error-text {
    color: var(--danger);
    font-size: var(--text-sm);
  }
  .not-found {
    text-align: center;
    padding: var(--sp-12) var(--sp-4);
  }
  .not-found h2 {
    margin-bottom: var(--sp-2);
  }
</style>
