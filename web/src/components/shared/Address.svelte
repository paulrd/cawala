<script>
  import { copyToClipboard } from '../../lib/utils.js';
  import { showToast } from '../../lib/stores.js';

  /**
   * Address — mono-font octal address with optional copy button.
   * @param {string} address
   * @param {boolean} [copyable=true]
   * @param {boolean} [truncate=false] - Truncate middle if long.
   * @param {string} [size='md'] - 'sm' | 'md' | 'lg'
   */
  let { address = '', copyable = true, truncate: doTruncate = false, size = 'md' } = $props();

  let copied = $state(false);

  async function handleCopy() {
    const ok = await copyToClipboard(address);
    if (ok) {
      copied = true;
      showToast('Address copied', 'ok', 2000);
      setTimeout(() => (copied = false), 1500);
    }
  }

  function truncateMiddle(str, keep = 5) {
    if (!str || str.length <= keep * 2 + 3) return str;
    return str.slice(0, keep) + '\u2026' + str.slice(-keep);
  }

  let displayAddress = $derived(doTruncate ? truncateMiddle(address) : address);
</script>

<span class="address address--{size}">
  <span class="address-text" title={address}>{displayAddress}</span>
  {#if copyable && address}
    <button
      type="button"
      class="copy-btn"
      onclick={handleCopy}
      title="Copy address"
      aria-label="Copy address"
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
  .address {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    font-family: var(--mono);
    letter-spacing: 0.03em;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 2px var(--sp-2);
    line-height: 1.4;
  }
  .address--sm { font-size: var(--text-xs); }
  .address--md { font-size: var(--text-sm); }
  .address--lg { font-size: var(--text-base); }
  .address-text {
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
