<script>
  import { formatBalance } from '../../lib/utils.js';

  /**
   * Balance — formatted balance with sign and color.
   * @param {number} amount
   * @param {boolean} [showSign=true]
   * @param {string} [size='md'] - 'sm' | 'md' | 'lg'
   */
  let { amount, showSign = true, size = 'md' } = $props();

  let display = $derived(formatBalance(amount, { showSign }));
  let colorClass = $derived(
    amount > 0 ? 'positive' : amount < 0 ? 'negative' : 'zero',
  );
</script>

<span class="balance balance--{size} balance--{colorClass}">
  {display}
</span>

<style>
  .balance {
    font-family: var(--mono);
    font-weight: 600;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  .balance--sm { font-size: var(--text-xs); }
  .balance--md { font-size: var(--text-sm); }
  .balance--lg { font-size: var(--text-xl); }
  .balance--positive { color: var(--ok); }
  .balance--negative { color: var(--danger); }
  .balance--zero { color: var(--muted); }
</style>
