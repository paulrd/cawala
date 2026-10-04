<script>
  import Card from '../shared/Card.svelte';
  import Balance from '../shared/Balance.svelte';
  import DataTable from '../shared/DataTable.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import LoadingSkeleton from '../shared/LoadingSkeleton.svelte';
  import ErrorState from '../shared/ErrorState.svelte';
  import Badge from '../shared/Badge.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import {
    nodeState,
    loadingState,
    errorState,
    ledgerState,
    administeredNode,
    adminCapabilities,
    adminLock,
    targetEpoch,
    showToast,
  } from '../../lib/stores.svelte.js';
  import {
    getAccounts,
    canAdministerValue,
    adminIssue,
    adminBurn,
    readPendingValueOp,
    clearPendingValueOp,
    retryPendingValueOp,
  } from '../../lib/api.js';
  import { valueReasonErrorVisible } from '../../lib/adminView.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

  let loaded = $state(false);
  let view = administeredNode;
  // Value actions need admin mode unlocked and pointed at a non-self ancestor.
  let canValue = $derived(canAdministerValue(view, adminCapabilities));
  let locked = $derived(!adminLock.unlocked);

  let selectedAccount = $state(null);
  let valueDialog = $state(null); // 'issue' | 'burn' | null
  let valueAmount = $state(0);
  let valueReason = $state('');
  let valueReasonTouched = $state(false);
  let valueBusy = $state(false);
  let pendingOp = $state(readPendingValueOp());

  let valueAmountValid = $derived(Number.isFinite(valueAmount) && valueAmount > 0);
  let valueReasonValid = $derived(valueReason.trim().length > 0);
  // The reason error is only shown after the field has been touched.
  let valueReasonError = $derived(valueReasonErrorVisible(valueReasonTouched, valueReasonValid));

  $effect(() => {
    void targetEpoch.value;
    pendingOp = readPendingValueOp();
    void loadData();
  });

  function handleSelectAccount(row) {
    if (row.type !== 'liability') return;
    selectedAccount = selectedAccount?.id === row.id ? null : row;
  }

  function openValueDialog(direction) {
    if (!selectedAccount) return;
    valueDialog = direction;
    valueAmount = 0;
    valueReason = '';
    valueReasonTouched = false;
  }

  /** Run one value call, routing a locked protected seed to the unlock dialog. */
  async function performValue(direction, accountId, amount, reason) {
    valueBusy = true;
    try {
      const result =
        direction === 'issue'
          ? await adminIssue(accountId, amount, reason)
          : await adminBurn(accountId, amount, reason);
      pendingOp = readPendingValueOp();
      if (result.status === 'duplicate') {
        showToast(
          `Already applied (seq ${result.seq}, ${String(result.entryHash).slice(0, 12)}…).`,
          'warn',
        );
      } else {
        showToast(
          `${direction === 'issue' ? 'Issued' : 'Burned'} ${amount}; new balance ${result.balanceAfter}.`,
          'ok',
        );
      }
      valueDialog = null;
      selectedAccount = null;
      await loadData();
    } catch (err) {
      pendingOp = readPendingValueOp();
      // Locked mode keeps its own gate: the message tells the operator where
      // to go instead of silently dropping the action.
      showToast(err?.message || 'Value operation failed.', 'danger');
    } finally {
      valueBusy = false;
    }
  }

  async function submitValue() {
    if (!selectedAccount) return;
    valueReasonTouched = true;
    if (!valueAmountValid || !valueReasonValid) return;
    await performValue(valueDialog, selectedAccount.id, valueAmount, valueReason.trim());
  }

  async function performRetryPending() {
    valueBusy = true;
    try {
      const result = await retryPendingValueOp();
      pendingOp = readPendingValueOp();
      if (result) showToast('Pending value operation applied.', 'ok');
      await loadData();
    } catch (err) {
      pendingOp = readPendingValueOp();
      showToast(err?.message || 'Retry failed.', 'danger');
    } finally {
      valueBusy = false;
    }
  }

  function handleRetryPending() {
    void performRetryPending();
  }

  function handleDiscardPending() {
    clearPendingValueOp();
    pendingOp = null;
    showToast('Pending value operation discarded.', 'warn');
  }

  async function loadData() {
    loadingState.accounts = true;
    errorState.accounts = null;
    try {
      const rows = await getAccounts();
      nodeState.accounts = rows;
      nodeState.accountsTruncated = Array.isArray(rows) ? Boolean(rows.truncated) : false;
      loaded = true;
    } catch (err) {
      errorState.accounts = err?.message || 'Failed to load accounts';
    } finally {
      loadingState.accounts = false;
    }
  }

  const columns = [
    { key: 'label', label: 'Account' },
    { key: 'type', label: 'Type',
      render: (v) => {
        const colors = { asset: 'var(--accent)', liability: 'var(--warn)', equity: 'var(--muted)' };
        const bgs = { asset: 'var(--accent-dim)', liability: 'var(--warn-dim)', equity: 'var(--bg-hover)' };
        return `<span style="display:inline-flex;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${bgs[v] || 'var(--bg-hover)'};color:${colors[v] || 'var(--muted)'}">${v}</span>`;
      }
    },
    { key: 'balance', label: 'Balance', align: 'right', mono: true,
      render: (v) => `<span style="font-family:var(--mono);font-weight:600;color:${v > 0 ? 'var(--ok)' : v < 0 ? 'var(--danger)' : 'var(--muted)'}">${v != null ? (v > 0 ? '+' : '') + v.toLocaleString() : '\u2014'}</span>` },
  ];

  let totalAssets = $derived(
    nodeState.accounts
      .filter((a) => a.type === 'asset')
      .reduce((sum, a) => sum + a.balance, 0),
  );
  let totalLiability = $derived(
    nodeState.accounts
      .filter((a) => a.type === 'liability')
      .reduce((sum, a) => sum + a.balance, 0),
  );
  // Equity is a row when the node publishes one, otherwise assets − liabilities
  // (the same derivation the mock data applies), so the equation is honest in
  // both modes.
  let equity = $derived(
    nodeState.accounts.find((a) => a.type === 'equity')?.balance ??
      totalAssets - totalLiability,
  );
  let hasRows = $derived(nodeState.accounts.length > 0);
  let balanceReady = $derived(ledgerState.balance != null);
  let truncated = $derived(Boolean(nodeState.accountsTruncated));

  let emptyMessage = $derived.by(() => {
    if (view.isSelf) {
      return 'Your verified balance will appear here once a receipt arrives from your leaf process.';
    }
    if (locked) {
      return 'Admin mode is locked, so this ancestor\u2019s books are hidden. Unlock it from the Admin tab to read them.';
    }
    if (!canValue) {
      return 'Step up the ancestor chain on the Admin tab to read and act on this node\u2019s books.';
    }
    return 'This node reported no accounts yet.';
  });
</script>

<div class="accounts-page">
  <Card title="Balance">
    {#snippet actions()}
      <button
        type="button"
        class="btn btn--ghost btn--sm"
        onclick={loadData}
        disabled={loadingState.accounts}
      >
        {loadingState.accounts ? 'Loading…' : 'Refresh'}
      </button>
    {/snippet}

    {#if locked && !view.isSelf}
      <EmptyState
        title="Admin mode is locked"
        message="This browser is pointed at an ancestor node. Unlock admin mode from the Admin tab to read its books, or step back down to this browser."
      />
    {:else if loadingState.accounts && !loaded}
      <LoadingSkeleton rows={2} />
    {:else if errorState.accounts}
      <ErrorState message={errorState.accounts} onRetry={loadData} />
    {:else if balanceReady}
      <div class="my-account">
        <div class="account-balance">
          <Balance amount={ledgerState.balance} size="lg" showSign={false} />
        </div>
        <p class="account-note text-sm muted">
          Your verified balance from the leaf process, updated when a balance receipt arrives.
        </p>
        <div class="account-meta">
          <Badge variant="ok" label="Verified" />
          {#if ledgerState.height != null}
            <span class="text-sm muted">Height {ledgerState.height}</span>
          {/if}
        </div>
        <button type="button" class="link-btn" onclick={() => navigate(ROUTES.MY_ACCOUNT)}>
          Go to My Account to send payments
        </button>
      </div>
    {:else if hasRows}
      <div class="my-account">
        <div class="account-balance">
          <Balance amount={equity} size="lg" showSign={false} />
        </div>
        <p class="account-note text-sm muted">
          Node equity (assets &minus; liabilities) from this node's accounting snapshot.
        </p>
      </div>
    {:else}
      <EmptyState title="No account data yet" message={emptyMessage} />
    {/if}
  </Card>

  <Card title="Accounting Equation">
    {#if hasRows}
      <div class="equation">
        <div class="eq-item">
          <span class="eq-label muted">Assets</span>
          <Balance amount={totalAssets} size="lg" />
        </div>
        <span class="eq-op muted">&minus;</span>
        <div class="eq-item">
          <span class="eq-label muted">Liabilities</span>
          <Balance amount={totalLiability} size="lg" />
        </div>
        <span class="eq-op muted">=</span>
        <div class="eq-item">
          <span class="eq-label muted">Equity</span>
          <Balance amount={equity} size="lg" />
        </div>
      </div>
    {:else}
      <p class="text-sm muted">
        The node accounting equation (assets &minus; liabilities = equity) applies to node
        operators. As a leaf user your balance comes from your parent node and is shown above.
      </p>
    {/if}
  </Card>

  <Card title="All Accounts">
    {#if locked && !view.isSelf}
      <p class="text-sm muted">No rows to show while admin mode is locked.</p>
    {:else if loadingState.accounts && !loaded}
      <LoadingSkeleton rows={3} />
    {:else if errorState.accounts}
      <ErrorState message="Failed to load accounts" onRetry={loadData} />
    {:else if !hasRows}
      <EmptyState title="No accounts" message={emptyMessage} />
    {:else}
      <DataTable
        {columns}
        rows={nodeState.accounts}
        selectedId={selectedAccount?.id ?? null}
        onRowClick={canValue ? handleSelectAccount : undefined}
      />

      {#if canValue}
        <div class="value-actions">
          <h4 class="value-heading">Value actions</h4>
          {#if !selectedAccount}
            <p class="text-sm muted">Select a liability account row to issue or burn value.</p>
          {:else}
            <p class="text-sm muted">
              Selected <code class="mono">{selectedAccount.label}</code>
              &middot; balance {selectedAccount.balance}
            </p>
            <div class="value-buttons">
              <button
                type="button"
                class="btn btn--ghost btn--sm"
                disabled={valueBusy}
                onclick={() => openValueDialog('issue')}
              >
                Issue&hellip;
              </button>
              <button
                type="button"
                class="btn btn--danger-outline btn--sm"
                disabled={valueBusy}
                onclick={() => openValueDialog('burn')}
              >
                Burn&hellip;
              </button>
            </div>
          {/if}

          {#if pendingOp}
            <div class="pending-note">
              <span class="text-xs muted">
                A value operation is pending: {pendingOp.direction} {pendingOp.amount} on
                {pendingOp.account || 'an account'}. Retry it to reuse the same idempotency key.
              </span>
              <div class="value-buttons">
                <button type="button" class="btn btn--ghost btn--sm" onclick={handleRetryPending}>
                  Retry
                </button>
                <button type="button" class="btn btn--ghost btn--sm" onclick={handleDiscardPending}>
                  Discard
                </button>
              </div>
            </div>
          {/if}
          <p class="text-xs muted">
            Issue is uncapped; burn is limited by the account&rsquo;s current balance.
          </p>
        </div>
      {/if}

      {#if truncated}
        <div class="truncated-note">
          <Badge variant="warn" label="Truncated" />
          <span class="text-xs muted">
            This node&rsquo;s account list exceeded its display limit and was shortened.
            The totals above still cover every balance.
          </span>
        </div>
      {/if}
    {/if}
  </Card>

  <ConfirmDialog
    open={valueDialog !== null}
    title={valueDialog === 'burn' ? 'Burn value?' : 'Issue value?'}
    message={`This ${valueDialog === 'burn' ? 'destroys' : 'creates'} value on ${view.label || view.nodeId || 'this node'} and changes its equity. Issue is uncapped; burn is limited by the account balance. This cannot be undone except by a compensating operation.`}
    confirmLabel={valueBusy ? 'Working…' : valueDialog === 'burn' ? 'Burn' : 'Issue'}
    variant={valueDialog === 'burn' ? 'danger' : 'default'}
    onConfirm={submitValue}
    onCancel={() => { valueDialog = null; }}
  >
    <div class="value-form">
      <label class="field-label" for="value-amount">Amount</label>
      <input
        id="value-amount"
        type="number"
        min="1"
        class="value-input"
        bind:value={valueAmount}
        disabled={valueBusy}
      />
      <label class="field-label" for="value-reason">Reason (required)</label>
      <input
        id="value-reason"
        type="text"
        class="value-input"
        placeholder="e.g. operator top-up"
        bind:value={valueReason}
        oninput={() => { valueReasonTouched = true; }}
        disabled={valueBusy}
      />
      {#if valueReasonError}
        <span class="text-xs" style="color: var(--danger);">A reason is required.</span>
      {/if}
    </div>
  </ConfirmDialog>

</div>

<style>
  .accounts-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }

  .my-account {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .account-balance {
    display: flex;
    align-items: baseline;
    gap: var(--sp-2);
  }
  .account-note {
    line-height: var(--leading-normal);
  }
  .account-meta {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
  }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--text-sm);
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
    text-align: left;
    align-self: flex-start;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  .equation {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
    flex-wrap: wrap;
  }
  .eq-item {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .eq-label {
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .eq-op {
    font-size: var(--text-2xl);
    font-weight: 300;
    line-height: 1;
  }

  .truncated-note {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    margin-top: var(--sp-3);
    flex-wrap: wrap;
  }

  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn--ghost {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .btn--sm {
    font-size: var(--text-xs);
    padding: var(--sp-1) var(--sp-3);
  }
  .btn--danger-outline {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .btn--danger-outline:hover:not(:disabled) {
    background: var(--danger-dim);
  }

  /* ── Value actions panel ─────────────────────────── */
  .value-actions {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-4);
    padding-top: var(--sp-4);
    border-top: 1px solid var(--border);
  }
  .value-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .value-buttons {
    display: flex;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
  .pending-note {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-3);
    border: 1px solid var(--warn);
    background: var(--warn-dim);
    border-radius: var(--radius-md);
  }
  .value-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .field-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .value-input {
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-sm);
  }
  .value-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .mono {
    font-family: var(--mono);
  }
</style>
