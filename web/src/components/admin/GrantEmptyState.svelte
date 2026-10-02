<script>
  import EmptyState from '../shared/EmptyState.svelte';
  import Badge from '../shared/Badge.svelte';
  import { ROUTES } from '../../lib/constants.js';
  import { navigate } from '../../lib/router.svelte.js';

  /**
   * GrantEmptyState — shown on admin pages when this browser cannot query the
   * selected node because it holds no usable admin key for it (none at all, or
   * the selected one is expired). One shared explanation instead of per-page
   * copies.
   *
   * @param {string} [title]
   * @param {string} [message]
   * @param {string} [command] the operator's grant command to show verbatim
   */
  let {
    title = 'A delegated admin key is required',
    message = 'Generate an admin key in Settings, then ask the node operator to grant it on the target node. This browser only ever holds the delegated key — never the node operator key or the ledger key.',
    command = 'cawala-node control admin grant --key <admin-pubkey> --label browser-admin',
  } = $props();
</script>

<div class="grant-setup">
  <div class="grant-setup-badge">
    <Badge variant="info" label="Delegated admin key" />
  </div>
  <EmptyState
    {title}
    {message}
    actionLabel="Open Settings"
    onAction={() => navigate(ROUTES.SETTINGS)}
  />
  <div class="grant-command">
    <span class="text-xs muted">Operator command</span>
    <code>{command}</code>
  </div>
</div>

<style>
  .grant-setup {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-2);
  }
  .grant-setup-badge {
    margin-bottom: calc(-1 * var(--sp-2));
  }
  .grant-command {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    align-items: center;
    width: 100%;
    max-width: 560px;
  }
  .grant-command code {
    display: block;
    width: 100%;
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font-family: var(--mono);
    font-size: var(--text-xs);
    color: var(--muted);
    overflow-x: auto;
    white-space: nowrap;
    text-align: center;
  }
</style>
