<script>
  import Badge from '../shared/Badge.svelte';
  import { statusBadge, ADMIN_STATUS, needsGrantBanner } from '../../lib/adminView.js';
  import { kindLabel, kindBadgeVariant } from '../../lib/nodeKind.js';

  /**
   * GrantStatusBanner — a full-width, persistent explanation of why admin
   * reads/writes are limited right now (expired, unreachable, revoked, or no
   * key for this target). Rendered by the context bar and by pages that gate
   * actions on a grant.
   *
   * @param {string} status one of ADMIN_STATUS
   * @param {string} [label] the node's display label
   * @param {number|null} [expiresAt]
   * @param {string} [kind]
   */
  let { status, label = '', expiresAt = null, kind = null } = $props();

  let badge = $derived(statusBadge(status));

  let message = $derived.by(() => {
    const who = label ? `for ${label}` : 'for this node';
    switch (status) {
      case ADMIN_STATUS.EXPIRED:
        return `The admin key ${who} has expired. Ask the node operator to grant a new key, then generate one in Settings.`;
      case ADMIN_STATUS.REVOKED:
        return `Access ${who} was revoked by the node operator. Reads and writes are disabled until a new key is granted.`;
      case ADMIN_STATUS.UNREACHABLE:
        return `The node ${who} did not answer the last query. The stored key may still be valid — retry, or check the node's address.`;
      case ADMIN_STATUS.NO_GRANT:
        return `This browser holds no admin key ${who}. Generate a key in Settings and ask the operator to grant it.`;
      default:
        return '';
    }
  });
</script>

{#if needsGrantBanner(status)}
  <div class="grant-banner grant-banner--{badge.variant}">
    <Badge variant={badge.variant} label={badge.label} />
    <div class="grant-banner-text">
      <span class="text-sm">{message}</span>
      {#if kind}
        <span class="text-xs muted">Last known kind: {kindLabel(kind)}{#if expiresAt} · key expires {new Date(expiresAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}{/if}</span>
      {/if}
    </div>
  </div>
{/if}

<style>
  .grant-banner {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
    padding: var(--sp-3) var(--sp-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-raised);
  }
  .grant-banner--danger {
    border-color: var(--danger);
    background: var(--danger-dim);
  }
  .grant-banner--warn {
    border-color: var(--warn);
    background: var(--warn-dim);
  }
  .grant-banner-text {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
</style>
