<script>
  import { truncateMiddle } from '../../lib/utils.js';
  import { copyToClipboard } from '../../lib/utils.js';
  import { showToast } from '../../lib/stores.js';

  /**
   * EndpointId — truncated iroh endpoint ID with copy button.
   * @param {string} id
   * @param {boolean} [copyable=true]
   * @param {boolean} [full=false] - Show full ID.
   */
  let { id = '', copyable = true, full = false } = $props();

  let copied = $state(false);

  async function handleCopy() {
    const ok = await copyToClipboard(id);
    if (ok) {
      copied = true;
      showToast('Endpoint ID copied', 'ok', 2000);
      setTimeout(() => (copied = false), 1500);
    }
  }

  let displayId = $derived(full ? id : truncateMiddle(id, 10));
</script>

<span class="endpoint-id">
  <span class="id-text" title={id}>{displayId}</span>
  {#if copyable && id}
    <button
      type="button"
      class="copy-btn"
      onclick={handleCopy}
      title="Copy endpoint ID"
      aria-label="Copy endpoint ID"
    >
      {#if copied}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
      {:else}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
      {/if}
    </button>
  {/if}
</span>

<style>
  .endpoint-id {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    font-family: var(--mono);
    font-size: var(--text-xs);
    letter-spacing: 0.02em;
    color: var(--muted);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 2px var(--sp-2);
    line-height: 1.4;
  }
  .id-text {
    white-space: nowrap;
  }
  .copy-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: 2px;
    border-radius: var(--radius-sm);
    transition: color var(--duration-fast) var(--ease);
    flex-shrink: 0;
  }
  .copy-btn:hover {
    color: var(--accent);
  }
</style>
