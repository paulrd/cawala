<script>
  import { onMount } from 'svelte';
  import Card from '../shared/Card.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Balance from '../shared/Balance.svelte';
  import Badge from '../shared/Badge.svelte';
  import EmptyState from '../shared/EmptyState.svelte';
  import { clientState, ledgerState, showToast } from '../../lib/stores.svelte.js';
  import {
    isMockMode,
    sendPayment,
    getPendingPayments,
    requestBalance,
    parseReceiveUri,
    getReceiveUri,
    leave,
    getLastControlEvent,
  } from '../../lib/api.js';
  import { ORDER_REJECT, ORDER_STATUS, ORDER_STATUS_LABELS, ORDER_STATUS_DESCRIPTIONS, CONTROL_EVENT, ROUTES } from '../../lib/constants.js';
  import { truncateMiddle, timeAgo, formatTime, copyToClipboard } from '../../lib/utils.js';
  import { navigate } from '../../lib/router.svelte.js';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';

  let isLive = $derived(!isMockMode());

  // ── Receive URI state ─────────────────────────────────────
  let receiveUri = $state(null);
  let receiveUriCopied = $state(false);
  let receiveUriLoading = $state(false);

  // ── Send form state ───────────────────────────────────────
  let sendUriInput = $state('');
  let sendAmount = $state('');
  let sendError = $state('');
  let sending = $state(false);
  let sendResult = $state(null); // { orderHash, status, reason, failedAt, ack }
  let sendPoller = $state(null);

  // Parsed payee from the receive URI (null until successfully parsed).
  let parsedPayee = $state(null);
  let parsingUri = $state(false);
  let parseError = $state('');

  // ── Balance staleness ─────────────────────────────────────
  let balanceFresh = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) < 30000
  );
  let balanceStale = $derived(
    ledgerState.verifiedAt != null && (Date.now() - ledgerState.verifiedAt) >= 30000
  );
  let balanceUnverified = $derived(ledgerState.balance == null);

  // ── URI parsing ───────────────────────────────────────────
  let _parseDebounce = null;

  function _onUriInputChange() {
    parsedPayee = null;
    parseError = '';
    if (_parseDebounce) clearTimeout(_parseDebounce);
    const raw = sendUriInput.trim();
    if (!raw) return;
    _parseDebounce = setTimeout(() => _parseUri(raw), 400);
  }

  async function _parseUri(raw) {
    parsingUri = true;
    parseError = '';
    try {
      const result = await parseReceiveUri(raw);
      parsedPayee = result;
    } catch (err) {
      parseError = err.message || 'Invalid receive URI.';
      parsedPayee = null;
    } finally {
      parsingUri = false;
    }
  }

  // ── Client-side validation ────────────────────────────────
  function validateSend() {
    const raw = sendAmount.trim();

    if (!parsedPayee) {
      sendError = 'Paste a valid receive URI first.';
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
      const { orderHash, ack } = await sendPayment(
        parsedPayee.nodeId,
        parsedPayee.address,
        Number(sendAmount.trim()),
        parsedPayee,
      );
      sendResult = {
        orderHash,
        ack,
        status: 'pending',
        reason: null,
        failedAt: null,
      };
      // Clear the form on submission.
      sendAmount = '';
      parsedPayee = null;
      sendUriInput = '';
      // Start polling for terminal status.
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
      if (match) {
        sendResult = {
          ...sendResult,
          status: match.status,
          reason: match.reason,
          failedAt: match.failedAt ?? null,
        };
        // Every non-pending status (including `indeterminate`) is terminal
        // client-side: stop polling and keep that card.
        if (match.status !== 'pending') {
          _stopSendPoller();
          return;
        }
      }
      // Stop after 60s to avoid infinite polling. Never overwrite an existing
      // terminal/indeterminate card with the generic timeout copy.
      if (attempts > 30) {
        _stopSendPoller();
        if (sendResult?.status === 'pending') {
          sendResult = {
            ...sendResult,
            reason: 'Status check timed out. The order may still be processing.',
          };
        }
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
    parsedPayee = null;
    parseError = '';
    sendUriInput = '';
    sendAmount = '';
  }

  function rejectionReasonText(reason) {
    if (!reason) return 'Unknown reason';
    const map = {
      [ORDER_REJECT.INSUFFICIENT_BALANCE]: 'Insufficient balance',
      [ORDER_REJECT.UNAUTHORIZED]: 'Unauthorized',
      [ORDER_REJECT.BAD_REQUEST]: 'Bad request',
      [ORDER_REJECT.EXPIRED]: 'Order expired',
      [ORDER_REJECT.ACCOUNT_NOT_OPENED]: 'Account not opened',
      [ORDER_REJECT.NOT_A_CHILD]: 'Recipient could not be reached',
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

  // ── Receive URI ───────────────────────────────────────────
  async function loadReceiveUri() {
    receiveUriLoading = true;
    try {
      receiveUri = await getReceiveUri();
    } catch {
      receiveUri = null;
    } finally {
      receiveUriLoading = false;
    }
  }

  async function handleCopyUri() {
    if (!receiveUri) return;
    const ok = await copyToClipboard(receiveUri);
    if (ok) {
      receiveUriCopied = true;
      showToast('Receive URI copied', 'ok', 2000);
      setTimeout(() => { receiveUriCopied = false; }, 2000);
    } else {
      showToast('Copy failed', 'danger', 3000);
    }
  }

  // ── Leave network state ───────────────────────────────────
  let leaveConfirmOpen = $state(false);
  let leaving = $state(false);
  let leaveError = $state('');
  let leaveResult = $state(null); // { status, delivery } | null

  // Detect the "detached" event from the control drain so the UI transitions
  // to the aftermath state even if the component was already mounted.
  let detachedSeen = $state(false);

  // Poll for the detached control event while the component is mounted.
  let _detachedPoller = $state(null);

  function _startDetachedPoller() {
    _stopDetachedPoller();
    _detachedPoller = setInterval(() => {
      if (detachedSeen) { _stopDetachedPoller(); return; }
      const ev = getLastControlEvent();
      if (ev?.kind === CONTROL_EVENT.DETACHED) {
        detachedSeen = true;
        _stopDetachedPoller();
      }
    }, 2000);
  }

  function _stopDetachedPoller() {
    if (_detachedPoller) {
      clearInterval(_detachedPoller);
      _detachedPoller = null;
    }
  }

  // Whether we are in the "not joined" state (address absent).
  let isJoined = $derived(!!clientState.address);
  // The detached aftermath: either we detected the event or we just completed
  // a leave() call and the address cleared.
  let hasLeft = $derived(detachedSeen || (leaveResult?.status === 'detached'));

  async function handleLeave() {
    leaveConfirmOpen = true;
  }

  async function confirmLeave() {
    leaveConfirmOpen = false;
    leaving = true;
    leaveError = '';
    try {
      const result = await leave();
      leaveResult = result;
      // The API clears clientState.address immediately. Also detect the
      // control event for the aftermath banner.
      const ev = getLastControlEvent();
      if (ev?.kind === CONTROL_EVENT.DETACHED) {
        detachedSeen = true;
      }
      showToast('Left the network.', 'ok');
    } catch (err) {
      leaveError = err.message || 'Failed to leave the network.';
    } finally {
      leaving = false;
    }
  }

  function cancelLeave() {
    leaveConfirmOpen = false;
  }

  // ── Mock transaction history ──────────────────────────────
  let mockTransactions = $state([
    { id: 1, type: 'transfer', to: '0.3.2', amount: 150, timestamp: new Date(Date.now() - 3600000).toISOString() },
    { id: 2, type: 'transfer', to: '0.3.3', amount: 75, timestamp: new Date(Date.now() - 86400000).toISOString() },
  ]);

  // ── Cleanup ───────────────────────────────────────────────
  // Reload the receive URI whenever this client becomes joined (its assigned
  // address appears or changes), so a page opened across the join does not stick
  // on "unavailable".
  $effect(() => {
    if (clientState.address) {
      loadReceiveUri();
    }
  });

  onMount(() => {
    _startDetachedPoller();
    return () => {
      _stopSendPoller();
      _stopDetachedPoller();
      if (_parseDebounce) clearTimeout(_parseDebounce);
    };
  });
</script>

<div class="my-account-page">
  <!-- ── Identity Card ──────────────────────────────────── -->
  <Card title="My Account">
    <div class="account-info">
      <div class="info-row">
        <span class="info-label muted">Endpoint ID</span>
        <div class="info-value">
          <EndpointId id={clientState.endpointId} full={true} />
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
          {:else if hasLeft}
            <span class="text-sm muted">Not assigned — you left this network.</span>
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

  <!-- ── Balance Card ───────────────────────────────────── -->
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

  <!-- ── My Receive URI Card ────────────────────────────── -->
  {#if isLive}
    <Card title="Receive payments">
      <div class="receive-section">
        {#if receiveUriLoading}
          <p class="text-sm muted">Loading receive URI&hellip;</p>
        {:else if receiveUri}
          <p class="text-sm">
            Share this link so others can pay you. They paste it into their send form, which resolves your node id and address automatically.
          </p>
          <div class="uri-row">
            <code class="uri-text">{receiveUri}</code>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={handleCopyUri}
            >
              {receiveUriCopied ? 'Copied' : 'Copy'}
            </button>
          </div>
        {:else}
          <p class="text-sm muted">
            Receive URI unavailable — join a leaf to get one.
          </p>
        {/if}
      </div>
    </Card>
  {/if}

  <!-- ── Send Payment Card ──────────────────────────────── -->
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
          {:else if sendResult.status === 'applied'}
            <div class="result-row result-success">
              <Badge variant="ok" label="Applied" />
              <span class="text-sm">
                The leaf reports this payment applied. Your signed balance receipt is the confirmation.
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
          {:else if sendResult.status === 'duplicate'}
            <div class="result-row result-success">
              <Badge variant="ok" label="Duplicate" />
              <span class="text-sm">This order was already applied. No double charge.</span>
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
          {:else if sendResult.status === 'unverified'}
            <div class="result-row result-unverified">
              <Badge variant="warn" label={ORDER_STATUS_LABELS[ORDER_STATUS.UNVERIFIED]} />
              <span class="text-sm">{ORDER_STATUS_DESCRIPTIONS[ORDER_STATUS.UNVERIFIED]}</span>
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
          {:else if sendResult.status === 'partial'}
            <div class="result-row result-partial">
              <Badge variant="warn" label="Sent, not confirmed" />
              <span class="text-sm">
                Your debit is committed but the payee was not credited. Reconciliation is in progress.
              </span>
            </div>
            <div class="result-detail">
              <span class="detail-label muted">Order hash</span>
              <code class="detail-value">{truncateMiddle(sendResult.orderHash, 12)}</code>
              {#if sendResult.failedAt}
                <span class="detail-hint text-xs muted">
                  Stopped at: {truncateMiddle(sendResult.failedAt, 8)}
                </span>
              {/if}
            </div>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onclick={resetSendForm}
            >
              Send another payment
            </button>
          {:else if sendResult.status === 'indeterminate'}
            <div class="result-row result-partial">
              <Badge variant="warn" label="Outcome unknown" />
              <span class="text-sm">
                Outcome unknown &mdash; your debit is committed; do not resend.
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
            <label class="field-label" for="send-uri">Payee receive URI</label>
            <input
              id="send-uri"
              type="text"
              class="field-input"
              placeholder="cawala://pay?to=...&addr=..."
              value={sendUriInput}
              oninput={(e) => { sendUriInput = e.target.value; _onUriInputChange(); }}
              disabled={sending}
              autocomplete="off"
              spellcheck="false"
            />
            <span class="field-hint text-xs muted">
              Paste the link the payee shared with you.
            </span>
          </div>

          {#if parsingUri}
            <div class="parse-status text-xs muted">Resolving&hellip;</div>
          {/if}

          {#if parseError}
            <div class="form-error" role="alert" aria-live="assertive">
              {parseError}
            </div>
          {/if}

          {#if parsedPayee}
            <div class="parsed-recipient">
              <div class="parsed-row">
                <span class="detail-label muted">Payee node</span>
                <div class="detail-value">
                  <EndpointId id={parsedPayee.nodeId} full={true} />
                </div>
              </div>
              <div class="parsed-row">
                <span class="detail-label muted">Payee address</span>
                <Address address={parsedPayee.address} size="sm" />
              </div>
              <div class="pin-signal">
                {#if parsedPayee.leafNodeId && parsedPayee.ledgerKeyHex}
                  <Badge variant="ok" label="Pinned" />
                  <span class="text-xs muted">Settlement will be verified against the payee leaf key.</span>
                {:else}
                  <Badge variant="muted" label="No pin" />
                  <span class="text-xs muted">Trust-on-first-use — no leaf key in the URI.</span>
                {/if}
              </div>
            </div>
          {/if}

          <div class="form-field">
            <label class="field-label" for="send-amount">Amount (whole units)</label>
            <input
              id="send-amount"
              type="text"
              class="field-input field-input--narrow"
              placeholder="0"
              bind:value={sendAmount}
              disabled={sending || !parsedPayee}
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
              disabled={sending || !parsedPayee || !sendAmount.trim()}
            >
              {#if sending}
                Sending&hellip;
              {:else}
                Send payment
              {/if}
            </button>
          </div>
        </form>
      {/if}
    </Card>
  {/if}

  <!-- ── Recent Activity Card ───────────────────────────── -->
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
  <!-- ── Leave Network Card ─────────────────────────────── -->
  {#if isLive}
    {#if isJoined && !hasLeft}
      <Card title="Network">
        <div class="leave-section">
          <div class="leave-info">
            <p class="text-sm">
              You are connected to a parent node.
              Address: <Address address={clientState.address} size="sm" />
            </p>
          </div>

          <div class="leave-danger-block">
            <h4 class="leave-heading">Leave the network</h4>
            <p class="leave-desc muted text-sm">
              This will disconnect you from your parent node. It cannot be undone.
            </p>
            <button
              type="button"
              class="btn btn--danger-outline"
              disabled={leaving}
              onclick={handleLeave}
            >
              {#if leaving}Leaving...{:else}Leave network{/if}
            </button>
          </div>

          {#if leaveError}
            <div class="leave-error" role="alert">
              {leaveError}
            </div>
          {/if}
        </div>
      </Card>
    {:else if hasLeft || (!isJoined && leaveResult?.status === 'detached')}
      <!-- Aftermath: user has left the network -->
      <Card title="Network">
        <div class="left-network-state">
          <div class="left-network-body">
            <h4 class="left-network-title">Not connected to a network</h4>
            <p class="text-sm muted">
              You are no longer part of a network. Your address has been cleared.
            </p>
            <div class="warn-box">
              <span class="warn-icon">!</span>
              <span>
                Any balance you still held with your former parent node stays on
                their books until you re-join and settle it.
              </span>
            </div>
            <p class="text-sm muted">
              You can join a different network, or re-join this one, using a new
              invitation from a node operator.
            </p>
            <button
              type="button"
              class="btn btn--primary"
              onclick={() => navigate(ROUTES.JOIN_FLOW)}
            >
              Join a network
            </button>
          </div>
        </div>
      </Card>
    {/if}
  {/if}

  <!-- Leave network confirm dialog -->
  <ConfirmDialog
    open={leaveConfirmOpen}
    title="Leave this network?"
    message="You will be disconnected from your parent node and lose your network address. Any balance you still hold with that parent stays on their books until you re-join and settle it. You can re-join this or another network later using a new invitation."
    confirmLabel="Leave network"
    cancelLabel="Stay"
    variant="danger"
    onConfirm={confirmLeave}
    onCancel={cancelLeave}
  />
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

  /* Receive URI */
  .receive-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .uri-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    min-width: 0;
  }
  .uri-text {
    font-family: var(--mono);
    font-size: var(--text-xs);
    color: var(--fg);
    word-break: break-all;
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 0;
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
  .field-hint {
    line-height: var(--leading-normal);
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
  .parse-status {
    line-height: var(--leading-normal);
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

  /* Parsed recipient confirmation */
  .parsed-recipient {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--ok-dim);
    border: 1px solid var(--ok);
    border-radius: var(--radius-md);
  }
  .parsed-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
  }
  .parsed-row .detail-label {
    min-width: 100px;
    flex-shrink: 0;
  }
  .parsed-row :global(.detail-value) {
    font-family: var(--mono);
    font-size: var(--text-sm);
  }
  .pin-signal {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding-top: var(--sp-1);
    border-top: 1px solid var(--border);
    margin-top: var(--sp-1);
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
  .btn--danger-outline {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .btn--danger-outline:hover:not(:disabled) {
    background: var(--danger-dim);
  }
  .btn--sm {
    font-size: var(--text-xs);
    padding: var(--sp-1) var(--sp-3);
  }

  /* Leave network section */
  .leave-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }
  .leave-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .leave-danger-block {
    padding: var(--sp-4);
    border: 1px solid color-mix(in srgb, var(--danger) 30%, var(--border));
    border-radius: var(--radius-lg);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .leave-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--danger);
    margin: 0;
  }
  .leave-desc {
    line-height: var(--leading-normal);
  }
  .leave-error {
    padding: var(--sp-2) var(--sp-3);
    background: var(--danger-dim);
    color: var(--danger);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  /* Left-network aftermath state */
  .left-network-state {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .left-network-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .left-network-title {
    font-size: var(--text-sm);
    font-weight: 600;
    margin: 0;
  }
  .warn-box {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--warn-dim);
    border: 1px solid color-mix(in srgb, var(--warn) 30%, transparent);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    color: var(--warn);
    line-height: var(--leading-normal);
  }
  .warn-icon {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--warn);
    color: #000;
    font-weight: 700;
    font-size: 11px;
    margin-top: 1px;
  }
</style>
