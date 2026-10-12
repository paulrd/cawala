<script>
  import { copyToClipboard } from '../../lib/utils.js';
  import { showToast } from '../../lib/stores.svelte.js';

  /**
   * MnemonicPhrase — the recovery-phrase word grid.
   *
   * Masked by default (words blurred behind a cover) so the phrase only
   * appears on an explicit, deliberate action; on reveal each word rises into
   * place with a short stagger. Numbered chips, mono, three columns.
   *
   * @param {string[]} words
   * @param {boolean} revealed - Whether the words are shown.
   * @param {() => void} onReveal - Called when the cover's reveal button is pressed.
   * @param {boolean} [copyable=true] - Show a copy button once revealed.
   */
  let { words = [], revealed = false, onReveal, copyable = true } = $props();

  let copied = $state(false);

  async function handleCopy() {
    const ok = await copyToClipboard(words.join(' '));
    if (ok) {
      copied = true;
      showToast('Recovery phrase copied', 'ok', 2000);
      setTimeout(() => (copied = false), 1500);
    }
  }
</script>

<div class="phrase" class:phrase--revealed={revealed}>
  <ol class="phrase-words" aria-hidden={!revealed ? 'true' : undefined} inert={!revealed}>
    {#each words as word, i (i)}
      <li class="word" style="--i: {i}">
        <span class="word-index">{i + 1}</span>
        <span class="word-text">{word}</span>
      </li>
    {/each}
  </ol>

  {#if !revealed}
    <div class="phrase-cover">
      <span class="cover-icon" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      </span>
      <p class="cover-text">Your words are hidden until you’re ready to write them down.</p>
      <button type="button" class="btn btn--primary" onclick={onReveal}>
        Show my words
      </button>
    </div>
  {:else if copyable}
    <div class="phrase-toolbar">
      <span class="phrase-hint text-xs muted">Write them down in this order.</span>
      <button
        type="button"
        class="copy-link"
        onclick={handleCopy}
        title="Copy all 12 words to the clipboard"
      >
        {#if copied}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
          Copied
        {:else}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          Copy words
        {/if}
      </button>
    </div>
  {/if}
</div>

<style>
  .phrase {
    position: relative;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--sp-4);
  }

  .phrase-words {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--sp-2);
    transition: filter var(--duration-normal) var(--ease);
  }
  .phrase--revealed .phrase-words {
    filter: none;
  }
  .phrase:not(.phrase--revealed) .phrase-words {
    filter: blur(7px);
    user-select: none;
    pointer-events: none;
  }

  .word {
    display: flex;
    align-items: baseline;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    min-width: 0;
  }
  .phrase--revealed .word {
    animation: word-rise 260ms var(--ease) both;
    animation-delay: calc(var(--i) * 28ms);
  }
  .word-index {
    flex-shrink: 0;
    font-size: var(--text-xs);
    color: var(--muted);
    font-variant-numeric: tabular-nums;
    width: 1.2em;
    text-align: right;
  }
  .word-text {
    font-family: var(--mono);
    font-size: var(--text-sm);
    color: var(--fg);
    letter-spacing: 0.02em;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  @keyframes word-rise {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  /* ── Masked cover ─────────────────────────────── */
  .phrase-cover {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--sp-3);
    padding: var(--sp-4);
    text-align: center;
    background: color-mix(in srgb, var(--bg) 82%, transparent);
    backdrop-filter: blur(1px);
    border-radius: var(--radius-lg);
  }
  .cover-icon {
    color: var(--muted);
    display: flex;
  }
  .cover-text {
    font-size: var(--text-sm);
    color: var(--muted);
    max-width: 300px;
    line-height: var(--leading-normal);
  }

  /* ── Toolbar once revealed ────────────────────── */
  .phrase-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
    margin-top: var(--sp-3);
    padding-top: var(--sp-3);
    border-top: 1px dashed var(--border);
  }
  .copy-link {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    background: none;
    border: none;
    color: var(--muted);
    font: inherit;
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    padding: 2px;
    border-radius: var(--radius-sm);
    transition: color var(--duration-fast) var(--ease);
    flex-shrink: 0;
  }
  .copy-link:hover {
    color: var(--accent);
  }

  /* ── Buttons (same shape as the app's) ────────── */
  .btn {
    padding: var(--sp-2) var(--sp-4);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease), opacity var(--duration-fast) var(--ease);
  }
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover {
    background: var(--accent-hover);
  }

  .text-xs { font-size: var(--text-xs); }
  .muted { color: var(--muted); }

  /* ── Responsive ───────────────────────────────── */
  @media (max-width: 520px) {
    .phrase-words {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
</style>
