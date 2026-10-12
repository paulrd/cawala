<script>
  import { copyToClipboard } from '../../lib/utils.js';
  import { showToast } from '../../lib/stores.svelte.js';

  /**
   * EthAddressBlock — the account address (EIP-55, 0x…), copyable, with a
   * one-line explanation of what an address is. Reveal animates once on
   * mount. The address is always real now (derived in wasm), so there is no
   * preview state.
   *
   * @param {string} address
   * @param {string} [label='Account address']
   * @param {string} [explanation=''] One line under the address.
   * @param {boolean} [animate=true] - Play the reveal animation.
   */
  let {
    address = '',
    label = 'Account address',
    explanation = '',
    animate = true,
  } = $props();

  let copied = $state(false);

  async function handleCopy() {
    if (!address) return;
    const ok = await copyToClipboard(address);
    if (ok) {
      copied = true;
      showToast('Address copied', 'ok', 2000);
      setTimeout(() => (copied = false), 1500);
    }
  }
</script>

<div class="eth-address" class:eth-address--animate={animate}>
  <div class="eth-label-row">
    <span class="eth-label">{label}</span>
  </div>

  <div class="eth-value" class:eth-value--empty={!address}>
    {#if address}
      <code class="eth-code" title={address}>{address}</code>
      <button
        type="button"
        class="copy-btn"
        onclick={handleCopy}
        title="Copy address"
        aria-label="Copy account address"
      >
        {#if copied}
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
        {:else}
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        {/if}
      </button>
    {:else}
      <span class="eth-empty">No address yet</span>
    {/if}
  </div>

  {#if explanation}
    <p class="eth-explanation">{explanation}</p>
  {/if}
</div>

<style>
  .eth-address {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .eth-address--animate {
    animation: address-in 360ms var(--ease) both;
  }
  @keyframes address-in {
    from {
      opacity: 0;
      transform: translateY(8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .eth-label-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }
  .eth-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .eth-value {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    min-width: 0;
    overflow: hidden;
    position: relative;
  }
  /* A one-time soft ring where the address first lands. */
  .eth-address--animate .eth-value::after {
    content: '';
    position: absolute;
    inset: -1px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    opacity: 0;
    pointer-events: none;
    animation: ring-pulse 900ms var(--ease) 120ms 1;
  }
  @keyframes ring-pulse {
    0% { opacity: 0.7; }
    100% { opacity: 0; }
  }

  .eth-code {
    flex: 1;
    min-width: 0;
    font-family: var(--mono);
    font-size: var(--text-sm);
    letter-spacing: 0.04em;
    background: none;
    border: none;
    padding: 0;
    border-radius: 0;
    overflow-x: auto;
    white-space: nowrap;
    color: var(--fg);
    scrollbar-width: none;
  }
  .eth-code::-webkit-scrollbar {
    display: none;
  }
  .eth-value--empty .eth-empty {
    color: var(--muted);
    font-size: var(--text-sm);
  }

  .copy-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: var(--sp-1);
    border-radius: var(--radius-sm);
    transition: color var(--duration-fast) var(--ease);
  }
  .copy-btn:hover {
    color: var(--accent);
  }

  .eth-explanation {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
</style>
