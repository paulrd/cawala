/**
 * Cawala M4 — Utility functions
 * Formatting, truncation, clipboard, date helpers.
 */

/**
 * Truncate a string in the middle, keeping prefix and suffix.
 * @param {string} str
 * @param {number} [keep=6] - Characters to keep at each end.
 * @returns {string}
 */
export function truncateMiddle(str, keep = 6) {
  if (!str) return '';
  if (str.length <= keep * 2 + 3) return str;
  return str.slice(0, keep) + '\u2026' + str.slice(-keep);
}

/**
 * Truncate with ellipsis at the end.
 * @param {string} str
 * @param {number} max
 * @returns {string}
 */
export function truncateEnd(str, max = 20) {
  if (!str) return '';
  if (str.length <= max) return str;
  return str.slice(0, max) + '\u2026';
}

/**
 * Format a balance amount with sign and locale-aware thousand separators.
 * @param {number} amount
 * @param {object} [opts]
 * @param {boolean} [opts.showSign=true]
 * @returns {string}
 */
export function formatBalance(amount, { showSign = true } = {}) {
  if (amount == null || isNaN(amount)) return '\u2014';
  const formatted = Math.abs(amount).toLocaleString('en-US');
  if (!showSign) return formatted;
  const sign = amount > 0 ? '+' : amount < 0 ? '\u2212' : '';
  return sign + formatted;
}

/**
 * Format a balance for display with color class.
 * @param {number} amount
 * @returns {{ text: string, cls: string }}
 */
export function balanceDisplay(amount) {
  if (amount == null || isNaN(amount)) return { text: '\u2014', cls: '' };
  const text = formatBalance(amount);
  const cls = amount > 0 ? 'positive' : amount < 0 ? 'negative' : 'zero';
  return { text, cls };
}

/**
 * Format a date to a short locale string.
 * @param {string|Date} date
 * @returns {string}
 */
export function formatDate(date) {
  if (!date) return '\u2014';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/**
 * Format a timestamp to time-only (HH:MM:SS).
 * @param {string|Date} date
 * @returns {string}
 */
export function formatTime(date) {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleTimeString('en-US', { hour12: false });
}

/**
 * Format a relative "time ago" string.
 * @param {string|Date} date
 * @returns {string}
 */
export function timeAgo(date) {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = Date.now();
  const diffMs = now - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return 'just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

/**
 * Copy text to clipboard. Returns true on success.
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers or insecure contexts
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

/**
 * Format a slot number for display.
 * @param {number} slot
 * @returns {string}
 */
export function formatSlot(slot) {
  return `slot ${slot}`;
}

/**
 * Generate a pseudo-random ID for temporary use.
 * @returns {string}
 */
export function tempId() {
  return Math.random().toString(36).slice(2, 10);
}
