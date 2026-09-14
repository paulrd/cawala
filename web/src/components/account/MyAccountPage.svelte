<script>
  import { onMount } from 'svelte';
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Balance from '../shared/Balance.svelte';
  import Badge from '../shared/Badge.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState, ledgerState, showToast } from '../../lib/stores.svelte.js';
  import { isMockMode, sendPayment, getPendingPayments, requestBalance } from '../../lib/api.js';
  import { ORDER_REJECT } from '../../lib/constants.js';
  import { truncateMiddle, timeAgo, formatTime } from '../../lib/utils.js';

  let isLive = $derived(!isMockMode());

  // ── Send form state ──────────────────────────────────────
  let sendTo = $state('');
  let sendAmount = $state('');
  let sendError = $state('');
  let sending = $state(false);
  let sendResult = $state(null); // { orderHash, status, reason, ack }
  let sendPoller = $state(null);

  // ── Balance staleness ────────────────────────────────────
  let balanceFresh = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) < 30000
  );
  let balanceStale = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) >= 30000
  );
  let balanceUnverified = $derived(ledgerState.balance == null);

  // ── Client-side validation ───────────────────────────────
  function validateSend() {
    const to = sendTo.trim();
    const raw = sendAmount.trim();

    if (!to) {
      sendError = 'Enter the recipient node id.';
      return false;
    }
    const amount = Number(raw);
    if (!Number.isFinite(amount)) {
      sendError = 'Enter a valid amount.';
      return false;
    }
    if (!Number.isInteger(amount)) {
      sendError = 'Amount must be a whole number.';
      return false;
    }
    if (amount <= 0) {
      sendError = 'Amount must be greater than zero.';
      return false;
    }
    if (amount > Number.MAX_SAFE_INTEGER) {
      sendError = 'Amount is too large.';
      return false;
    }
    sendError = '';
    return true;
  }

  async function handleSubmit() {
    if (!validateSend()) return;
    sending = true;
    sendError = '';
    sendResult = null;

    try {
      const { orderHash, ack } = await sendPayment(sendTo.trim(), Number(sendAmount.trim()));
      sendResult = {
        orderHash,
        ack,
        status: 'pending',
        reason: null,
      };
      // Clear the form on submission
      sendTo = '';
      sendAmount = '';
      // Start polling for terminal status
      _startSendPoller(orderHash);
    } catch (err) {
      sendError = err.message || 'Payment failed.';
    } finally {
      sending = false;
    }
  }

  function _startSendPoller(orderHash) {
    _stopSendPoller();
    let attempts = 0;
    sendPoller = setInterval(() => {
      attempts++;
      const payments = getPendingPayments();
      const match = payments.find((p) => p.orderHash === orderHash);
      if (match && match.status !== 'pending') {
        _stopSendPoller();
        sendResult = {
          ...sendResult,
          status: match.status,
          reason: match.reason,
        };
      }
      // Stop after 60s to avoid infinite polling
      if (attempts > 30) {
        _stopSendPoller();
        sendResult = {
          ...sendResult,
          status: 'pending',
          reason: 'Status check timed out. The order may still be processing.',
        };
      }
    }, 2000);
  }

  function _stopSendPoller() {
    if (sendPoller) {
      clearInterval(sendPoller);
      sendPoller = null;
    }
  }

  function resetSendForm() {
    sendResult = null;
    sendError = '';
  }

  function rejectionReasonText(reason) {
    if (!reason) return 'Unknown reason';
    const map = {
      [ORDER_REJECT.INSUFFICIENT_BALANCE]: 'Insufficient balance',
      [ORDER_REJECT.UNAUTHORIZED]: 'Unauthorized',
      [ORDER_REJECT.BAD_REQUEST]: 'Bad request',
      [ORDER_REJECT.EXPIRED]: 'Order expired',
      [ORDER_REJECT.ACCOUNT_NOT_OPENED]: 'Account not opened',
      [ORDER_REJECT.NOT_A_CHILD]: 'Recipient is not a child of this leaf',
      [ORDER_REJECT.INTERNAL]: 'Internal error',
    };
    return map[reason] || reason;
  }

  function handleRetry() {
    sendResult = null;
    sendError = '';
  }

  async function handleRefreshBalance() {
    await requestBalance();
    showToast('Balance refresh requested', 'info', 2000);
  }

  // ── Mock transaction history ─────────────────────────────
  let mockTransactions = $state([
    { id: 1, type: 'transfer', to: '0.3.2', amount: 150, timestamp: new Date(Date.now() - 3600000).toISOString() },
    { id: 2, type: 'transfer', to: '0.3.3', amount: 75, timestamp: new Date(Date.now() - 86400000).toISOString() },
  ]);

  // ── Cleanup ──────────────────────────────────────────────

  onMount(() => {
    return () => _stopSendPoller();
  });
</script>

<div class="my-account-page">
  <!-- ── Identity Card ─────────────────────────────────── -->
  <Card title="My Account">
    <div class="account-info">
      <div class="info-row">
        <span class="info-label muted">Endpoint ID</span>
        <div class="info-value">
          <EndpointId id={clientState.endpointId} full={true} />
          {#if isLive}
            <p class="info-hint">
              Share this id so others can send you payments.
            </p>
          {/if}
        </div>
      </div>

      <div class="info-row">
        <span class="info-label muted">Address</span>
        <div class="info-value">
          {#if clientState.address}
            <Address address={clientState.address} size="md" />
            <p class="info-hint">
              Assigned by your parent node when you joined.
            </p>
          {:else}
            <span class="text-sm muted">Not assigned yet — waiting for join approval.</span>
          {/if}
        </div>
      </div>

      <div class="info-row">
        <span class="info-label muted">Mode</span>
        <Badge variant={isLive ? 'ok' : 'warn'} label={isLive ? 'Live' : 'Mock'} />
      </div>
    </div>
  </Card>

  <!-- ── Balance Card ──────────────────────────────────── -->
  <Card title="Verified Balance">
    {#if isLive}
      <div class="balance-section">
        {#if balanceUnverified}
          <div class="balance-loading">
            <div class="balance-value">
              <span class="balance-placeholder">&mdash;</span>
            </div>
            <p class="balance-status muted">
              Balance not yet verified. Waiting for a receipt from your leaf.
            </p>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={handleRefreshBalance}
            >
              Request balance
            </button>
          </div>
        {:else}
          <div class="balance-section">
            <div class="balance-value">
              <Balance amount={ledgerState.balance} size="lg" showSign={false} />
            </div>

            <div class="balance-meta">
              {#if balanceFresh}
                <Badge variant="ok" label="Verified" />
              {:else if balanceStale}
                <Badge variant="warn" label="Stale — re-verifying" />
              {/if}

              {#if ledgerState.height != null}
                <span class="meta-item text-sm muted">
                  Height: {ledgerState.height}
                </span>
              {/if}

              {#if ledgerState.verifiedAt}
                <span class="meta-item text-sm muted">
                  Last verified: {timeAgo(new Date(ledgerState.verifiedAt))}
                </span>
              {/if}
            </div>

            {#if ledgerState.error}
              <div class="balance-error">
                <Badge variant="danger" label="Error" />
                <span class="text-sm">{ledgerState.error}</span>
              </div>
            {/if}

            {#if ledgerState.pending > 0}
              <div class="pending-indicator">
                <Badge variant="info" label="{ledgerState.pending} pending" />
                <span class="text-sm muted">Orders awaiting confirmation.</span>
              </div>
            {/if}

            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={handleRefreshBalance}
            >
              Refresh balance
            </button>
          </div>
        {/if}
      </div>
    {:else}
      <!-- Mock mode: show a sample balance -->
      <div class="balance-section">
        <div class="balance-value">
          <Balance amount={1200} size="lg" showSign={false} />
        </div>
        <div class="balance-meta">
          <Badge variant="ok" label="Verified" />
          <span class="meta-item text-sm muted">Height: 42</span>
        </div>
      </div>
    {/if}
  </Card>

  <!-- ── Send Payment Card ─────────────────────────────── -->
  {#if isLive}
    <Card title="Send payment">
      {#if sendResult}
        <div class="send-result" role="status" aria-live="polite">
          {#if sendResult.status === 'pending'}
            <div class="result-row result-pending">
              <Badge variant="info" label="Pending" />
              <span class="text-sm">Order submitted. Waiting for confirmation&hellip;</span>
            </div>
            <div class="result-detail">
              <span class="detail-label muted">Order hash</span>
              <code class="detail-value">{truncateMiddle(sendResult.orderHash, 12)}</code>
            </div>
          {:else if sendResult.status === 'applied' || sendResult.status === 'duplicate'}
            <div class="result-row result-success">
              <Badge variant="ok" label={sendResult.status === 'duplicate' ? 'Duplicate (already applied)' : 'Applied'} />
              <span class="text-sm">
                {sendResult.status === 'duplicate'
                  ? 'This order was already applied.'
                  : 'Payment applied.'}
              </span>
            </div>
            <div class="result-detail">
              <span class="detail-label muted">Order hash</span>
              <code class="detail-value">{truncateMiddle(sendResult.orderHash, 12)}</code>
            </div>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={resetSendForm}
            >
              Send another payment
            </button>
          {:else if sendResult.status === 'rejected'}
            <div class="result-row result-rejected">
              <Badge variant="danger" label="Rejected" />
              <span class="text-sm">
                Payment was rejected: {rejectionReasonText(sendResult.reason)}.
              </span>
            </div>
            <div class="result-detail">
              <span class="detail-label muted">Order hash</span>
              <code class="detail-value">{truncateMiddle(sendResult.orderHash, 12)}</code>
              <span class="detail-hint text-xs muted">Provide this hash if you need support.</span>
            </div>
            <button
              type="button"
              class="btn btn--primary btn--sm"
              onclick={handleRetry}
            >
              Retry payment
            </button>
          {:else}
            <!-- Still pending after timeout -->
            <div class="result-row result-pending">
              <Badge variant="warn" label="Still pending" />
              <span class="text-sm">{sendResult.reason || 'Status check timed out.'}</span>
            </div>
            <div class="result-detail">
              <span class="detail-label muted">Order hash</span>
              <code class="detail-value">{truncateMiddle(sendResult.orderHash, 12)}</code>
            </div>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={resetSendForm}
            >
              Send another payment
            </button>
          {/if}
        </div>
      {:else}
        <form class="send-form" onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} aria-label="Send payment form">
          <div class="form-field">
            <label class="field-label" for="send-to">Recipient node id</label>
            <input
              id="send-to"
              type="text"
              class="field-input"
              placeholder="z6Mk..."
              bind:value={sendTo}
              disabled={sending}
              autocomplete="off"
              spellcheck="false"
            />
          </div>

          <div class="form-field">
            <label class="field-label" for="send-amount">Amount (whole units)</label>
            <input
              id="send-amount"
              type="text"
              class="field-input field-input--narrow"
              placeholder="0"
              bind:value={sendAmount}
              disabled={sending}
              inputmode="numeric"
              autocomplete="off"
            />
          </div>

          {#if sendError}
            <div class="form-error" role="alert" aria-live="assertive">
              {sendError}
            </div>
          {/if}

          <div class="form-actions">
            <button
              type="submit"
              class="btn btn--primary"
              disabled={sending || !sendTo.trim() || !sendAmount.trim()}
            >
              {#if sending}
                Sending&hellip;
              {:else}
                Send payment
              {/if}
            </button>
          </div>

          <p class="form-note text-xs muted">
            Only same-leaf payments are supported. The recipient must share their node id.
          </p>
        </form>
      {/if}
    </Card>
  {/if}

  <!-- ── Recent Activity Card ──────────────────────────── -->
  <Card title="Recent Transactions">
    {#if isLive}
      {#if ledgerState.activity.length === 0 && ledgerState.pending === 0}
        <EmptyState
          title="No transactions yet"
          message="Only payments sent from this browser are listed here. Incoming value updates your balance but is not listed as a separate row."
        />
      {:else}
        <div class="activity-list">
          {#each ledgerState.activity as entry (entry.id)}
            <div class="activity-row">
              <div class="activity-type">
                <Badge variant="info" label="Transfer" />
              </div>
              <div class="activity-detail">
                <span class="activity-amount">
                  <Balance amount={entry.amount} size="sm" />
                </span>
                {#if entry.to}
                  <span class="activity-to text-sm muted">
                    to {truncateMiddle(entry.to, 8)}
                  </span>
                {/if}
              </div>
              <div class="activity-time text-xs muted">
                {formatTime(entry.timestamp)}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    {:else}
      <!-- Mock mode: show sample transactions -->
      <div class="activity-list">
        {#each mockTransactions as tx (tx.id)}
          <div class="activity-row">
            <div class="activity-type">
              <Badge variant="info" label="Transfer" />
            </div>
            <div class="activity-detail">
              <span class="activity-amount">
                <Balance amount={tx.amount} size="sm" />
              </span>
              <span class="activity-to text-sm muted">
                to {tx.to}
              </span>
            </div>
            <div class="activity-time text-xs muted">
              {formatTime(tx.timestamp)}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </Card>
</div>

<style>
  .my-account-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .account-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .info-row {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-4);
  }
  .info-label {
    min-width: 100px;
    font-size: var(--text-sm);
    font-weight: 500;
    padding-top: 2px;
    flex-shrink: 0;
  }
  .info-value {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .info-hint {
    font-size: var(--text-xs);
    color: var(--muted);
    line-height: var(--leading-normal);
  }

  /* Balance */
  .balance-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .balance-value {
    display: flex;
    align-items: baseline;
    gap: var(--sp-2);
  }
  .balance-placeholder {
    font-family: var(--mono);
    font-size: var(--text-xl);
    color: var(--muted);
    font-weight: 600;
  }
  .balance-loading {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .balance-meta {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .meta-item {
    display: inline-flex;
    align-items: center;
  }
  .balance-error {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3);
    background: var(--danger-dim);
    border-radius: var(--radius-md);
  }
  .pending-indicator {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }

  /* Send form */
  .send-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }
  .form-field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .field-label {
    font-size: var(--text-sm);
    font-weight: 500;
    color: var(--fg);
  }
  .field-input {
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font: inherit;
    font-family: var(--mono);
    font-size: var(--text-sm);
    transition: border-color var(--duration-fast) var(--ease);
  }
  .field-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .field-input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .field-input--narrow {
    max-width: 200px;
  }
  .form-error {
    padding: var(--sp-2) var(--sp-3);
    background: var(--danger-dim);
    color: var(--danger);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }
  .form-actions {
    display: flex;
    gap: var(--sp-3);
  }
  .form-note {
    line-height: var(--leading-normal);
  }

  /* Send result */
  .send-result {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }
  .result-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
  }
  .result-detail {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .detail-label {
    font-size: var(--text-xs);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .detail-value {
    font-family: var(--mono);
    font-size: var(--text-sm);
    word-break: break-all;
  }
  .detail-hint {
    margin-top: var(--sp-1);
  }

  /* Activity */
  .activity-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .activity-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-2) 0;
    border-bottom: 1px solid var(--border);
  }
  .activity-row:last-child {
    border-bottom: none;
  }
  .activity-type {
    flex-shrink: 0;
  }
  .activity-detail {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex: 1;
    min-width: 0;
  }
  .activity-amount {
    flex-shrink: 0;
  }
  .activity-to {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .activity-time {
    flex-shrink: 0;
    text-align: right;
  }

  /* Shared button styles */
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
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover:not(:disabled) {
    background: var(--accent-hover);
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
</style>
