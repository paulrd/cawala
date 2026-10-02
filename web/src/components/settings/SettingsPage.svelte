<script>
  import Card from '../shared/Card.svelte';
  import AdminNodeRow from '../admin/AdminNodeRow.svelte';
  import Address from '../shared/Address.svelte';
  import EndpointId from '../shared/EndpointId.svelte';
  import Badge from '../shared/Badge.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import ConnectionIndicator from '../shared/ConnectionIndicator.svelte';
  import { clientState, ledgerState, apiCapabilities, administeredNode, showToast } from '../../lib/stores.svelte.js';
  import {
    isMockMode,
    isIdentityPersistent,
    getCapabilities,
    exportIdentityBundle,
    inspectIdentityBundle,
    importIdentityBundle,
    wipeIdentity,
    listAdministeredNodes,
    setAdministeredNode,
    configureAdminNode,
    removeAdminNode,
    applyAdminBundle,
    lockAdmin,
    protectValueSeed,
  } from '../../lib/api.js';
  import { copyToClipboard } from '../../lib/utils.js';
  import { isValidNodeAddr } from '../../lib/adminKeys.js';
  import UnlockAdminKeyDialog from '../shared/UnlockAdminKeyDialog.svelte';
  import { buildSelectorItems } from '../../lib/adminView.js';

  let caps = $derived(getCapabilities());
  let mock = $derived(isMockMode());
  let liveNoSeed = $derived(!mock && !caps.identityPersistent);

  // ── Export state ──────────────────────────────────────────
  let exportPassphrase = $state('');
  let exportPassphraseConfirm = $state('');
  let exportBusy = $state(false);

  let exportPassphraseValid = $derived(exportPassphrase.length >= 12);
  let exportConfirmValid = $derived(exportPassphrase === exportPassphraseConfirm && exportPassphraseConfirm.length > 0);
  let exportReady = $derived(exportPassphraseValid && exportConfirmValid && !exportBusy);

  async function handleExport() {
    if (!exportReady) return;
    exportBusy = true;
    try {
      const bundle = await exportIdentityBundle(exportPassphrase);
      const id = clientState.endpointId || 'unknown';
      const filename = `cawala-identity-${id.slice(0, 12)}.json`;
      const blob = new Blob([bundle], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Identity exported and downloaded.', 'ok');
      exportPassphrase = '';
      exportPassphraseConfirm = '';
    } catch (err) {
      showToast(err?.message || 'Export failed.', 'danger');
    } finally {
      exportBusy = false;
    }
  }

  // ── Import state ──────────────────────────────────────────
  let importText = $state('');
  let importPassphrase = $state('');
  let importBusy = $state(false);
  let importPreview = $state(null); // { version, nodeId } | null
  let importError = $state(null);
  let importConfirmOpen = $state(false);

  let importCanPreview = $derived(importText.trim().length > 0 && !mock);
  let importCanSubmit = $derived(importPreview !== null && importPassphrase.length > 0 && !importBusy);

  function handleImportFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      importText = typeof reader.result === 'string' ? reader.result : '';
      runImportPreview();
    };
    reader.readAsText(file);
  }

  function runImportPreview() {
    importError = null;
    importPreview = null;
    const text = importText.trim();
    if (!text) return;
    try {
      const meta = inspectIdentityBundle(text);
      importPreview = meta;
    } catch (err) {
      importError = err?.message || 'Could not read this bundle.';
    }
  }

  function handleImportConfirm() {
    importConfirmOpen = true;
  }

  async function doImport() {
    importConfirmOpen = false;
    importBusy = true;
    try {
      await importIdentityBundle(importText.trim(), importPassphrase);
      showToast('Identity imported. Reloading...', 'ok');
      window.location.reload();
    } catch (err) {
      showToast(err?.message || 'Import failed. Check the passphrase.', 'danger');
      importBusy = false;
    }
  }

  // ── Wipe state ────────────────────────────────────────────
  let wipeConfirmOpen = $state(false);
  let wipeBusy = $state(false);

  async function doWipe() {
    wipeConfirmOpen = false;
    wipeBusy = true;
    try {
      await wipeIdentity();
      showToast('Identity removed. Reloading...', 'ok');
      window.location.reload();
    } catch (err) {
      showToast(err?.message || 'Wipe failed.', 'danger');
      wipeBusy = false;
    }
  }

  // ── Admin node state ──────────────────────────────────────
  let adminNodes = $state([]);
  let adminBusy = $state(false);
  let configureNodeId = $state('');
  let configureLabel = $state('');
  let configureDays = $state(7);
  let configureNodeAddr = $state('');
  let configureResult = $state(null); // { nodeId, adminPubHex } | null
  let removeConfirmOpen = $state(false);
  let removeTarget = $state(null); // nodeId string
  let bundleUri = $state('');
  let bundleBusy = $state(false);
  let bundleMessage = $state(null); // { kind: 'ok' | 'danger', text } | null

  // ── Value key protection ──────────────────────────────────
  let protectDialog = $state(null); // { nodeId, mode: 'protect' } | null
  let protectBusy = $state(false);
  let protectError = $state(null);

  function openProtect(nodeId) {
    protectDialog = { nodeId, mode: 'protect' };
    protectError = null;
  }

  async function handleProtectSubmit(passphrase) {
    if (!protectDialog) return;
    protectBusy = true;
    protectError = null;
    try {
      // Fail closed: `protectValueSeed` verifies the wrapped row was persisted
      // before it resolves, so a storage failure never reports success.
      await protectValueSeed(protectDialog.nodeId, passphrase);
      showToast('Value key protected.', 'ok');
      protectDialog = null;
      await loadAdminNodes();
    } catch (err) {
      protectError = err?.message || 'Could not protect the value key.';
    } finally {
      protectBusy = false;
    }
  }

  function handleLock(nodeId) {
    lockAdmin(nodeId);
    showToast('Value key locked.', 'warn');
    loadAdminNodes();
  }

  let configureNodeAddrValid = $derived(
    configureNodeAddr === '' || isValidNodeAddr(configureNodeAddr),
  );
  let configureNodeAddrHint = $derived(
    configureNodeAddr && !configureNodeAddrValid
      ? 'Enter a dotted octal address such as 0 or 0.3.1 (one digit 0-7 per level).'
      : null,
  );

  async function loadAdminNodes() {
    if (mock) return;
    try {
      adminNodes = listAdministeredNodes();
    } catch {
      adminNodes = [];
    }
  }

  $effect(() => {
    if (!mock) loadAdminNodes();
  });

  /**
   * The exact rows the header selector shows (self + granted nodes), so the
   * Settings list can never drift from the selector it feeds.
   */
  let selectorGroups = $derived(
    buildSelectorItems({
      self: { endpointId: clientState.endpointId },
      mock,
      nodes: adminNodes,
      selected: administeredNode.nodeId,
    }).groups,
  );

  // Only value-scoped keys can/must be protected; joins/topology stay plaintext.
  let valueAdminNodes = $derived(adminNodes.filter((node) => node.scopes?.includes('value')));

  /** Switch the whole console to this node (same action as the selector). */
  function handleSelectAdmin(item) {
    try {
      setAdministeredNode(item.id);
      showToast(`Now administering ${item.label}.`, 'ok');
    } catch (err) {
      showToast(err?.message || 'Could not switch the administered node.', 'danger');
    }
  }

  function validateNodeId(id) {
    return /^[0-9a-fA-F]{64}$/.test(id);
  }

  let configureReady = $derived(
    validateNodeId(configureNodeId) &&
    configureDays > 0 &&
    configureNodeAddrValid &&
    !adminBusy,
  );

  async function handleConfigure() {
    if (!configureReady) return;
    adminBusy = true;
    try {
      const expirySeconds = Math.round(configureDays * 24 * 60 * 60);
      const nodeAddr = configureNodeAddr.trim() || null;
      const result = await configureAdminNode(configureNodeId, {
        expirySeconds,
        label: configureLabel.trim() || null,
        nodeAddr,
      });
      configureResult = result;
      showToast('Admin key generated. Copy the public key and ask the operator to grant it.', 'ok');
      await loadAdminNodes();
    } catch (err) {
      showToast(err?.message || 'Failed to generate admin key.', 'danger');
    } finally {
      adminBusy = false;
    }
  }

  function handleCopyPubKey() {
    if (configureResult) {
      copyToClipboard(configureResult.adminPubHex).then((ok) => {
        showToast(ok ? 'Public key copied.' : 'Copy failed.', ok ? 'ok' : 'warn');
      });
    }
  }

  function handleCopyCommand() {
    if (!configureResult) return;
    const cmd = `cawala-node control admin grant --key ${configureResult.adminPubHex} --label ${configureLabel.trim() || 'browser-admin'}`;
    copyToClipboard(cmd).then((ok) => {
      showToast(ok ? 'Command copied.' : 'Copy failed.', ok ? 'ok' : 'warn');
    });
  }

  async function handleApplyBundle() {
    const uri = bundleUri.trim();
    if (!uri || bundleBusy) return;
    bundleBusy = true;
    bundleMessage = null;
    try {
      const applied = await applyAdminBundle(uri);
      bundleMessage = {
        kind: 'ok',
        text: `Imported operator-signed grant for ${applied.nodeId.slice(0, 12)}… — scopes: ${applied.scopes.join(', ')}.`,
      };
      bundleUri = '';
      await loadAdminNodes();
    } catch (err) {
      bundleMessage = { kind: 'danger', text: err?.message || 'Could not import this bundle.' };
    } finally {
      bundleBusy = false;
    }
  }

  function handleRemoveAdmin(nodeId) {
    removeTarget = nodeId;
    removeConfirmOpen = true;
  }

  function doRemoveAdmin() {
    if (!removeTarget) return;
    try {
      removeAdminNode(removeTarget);
      showToast('Admin node removed.', 'ok');
      loadAdminNodes();
    } catch (err) {
      showToast(err?.message || 'Failed to remove admin node.', 'danger');
    }
    removeConfirmOpen = false;
    removeTarget = null;
  }

</script>

<div class="settings-page">
  <Card title="Connection">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Status</span>
        <ConnectionIndicator status={clientState.connectionStatus} />
      </div>
      <div class="setting-row">
        <span class="setting-label">Mode</span>
        <Badge variant={isMockMode() ? 'warn' : 'ok'} label={isMockMode() ? 'Mock (no live node)' : 'Live'} />
      </div>
    </div>
  </Card>

  <Card title="Identity">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Endpoint ID</span>
        <EndpointId id={clientState.endpointId} full={true} />
      </div>
      <div class="setting-row">
        <span class="setting-label">Address</span>
        {#if clientState.address}
          <Address address={clientState.address} size="md" />
        {:else}
          <span class="text-sm muted">Not assigned yet</span>
        {/if}
      </div>
      {#if !isMockMode()}
        <div class="setting-row">
          <span class="setting-label">Identity</span>
          {#if caps.identityPersistent}
            <Badge variant="ok" label="Persisted" />
          {:else}
            <div class="persistence-warn">
              <Badge variant="warn" label="Session only" />
              <span class="text-xs muted">Identity won't persist after closing this tab (storage unavailable).</span>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </Card>

  {#if !isMockMode() && ledgerState.pinnedLedger}
    <Card title="Leaf Ledger Trust">
      <div class="settings-section">
        <div class="setting-row">
          <span class="setting-label">Pinned ledger</span>
          <code class="text-sm" style="word-break: break-all; font-family: var(--mono);">
            {ledgerState.pinnedLedger}
          </code>
        </div>
        <p class="muted text-sm" style="margin-top: var(--sp-1);">
          This is the leaf's ledger public key, pinned on first use (TOFU). Your balance and payment receipts are verified against this key.
        </p>
      </div>
    </Card>
  {/if}

  {#if caps.multiTabWarning}
    <Card title="Multi-Tab" variant="warn">
      <div class="settings-section">
        <p class="text-sm" style="color: var(--warn);">
          {caps.multiTabWarning}
        </p>
      </div>
    </Card>
  {/if}

  <Card title="Identity Portability">
    <div class="settings-section">

      {#if mock}
        <div class="muted text-sm">
          Identity portability is not available in mock mode.
        </div>
      {:else}
        <p class="muted text-sm">
          Your identity key controls this account. Exporting encrypts it along with
          join and ledger state into a single file you can import on another device.
        </p>

        <!-- Export -->
        <div class="identity-block">
          <h4 class="identity-heading">Export identity</h4>
          {#if liveNoSeed}
            <p class="muted text-sm">
              This device has no stored seed (private browsing or storage unavailable). Export is not possible.
            </p>
          {:else}
            <p class="muted text-sm">
              Choose a passphrase of at least 12 characters. It encrypts the bundle locally
              and is never sent anywhere. If you lose it, the bundle cannot be recovered.
            </p>
            <div class="field">
              <label class="field-label" for="export-pass">Passphrase</label>
              <input
                id="export-pass"
                type="password"
                class="field-input"
                placeholder="At least 12 characters"
                bind:value={exportPassphrase}
                disabled={exportBusy}
                autocomplete="new-password"
              />
            </div>
            <div class="field">
              <label class="field-label" for="export-pass-confirm">Confirm passphrase</label>
              <input
                id="export-pass-confirm"
                type="password"
                class="field-input"
                placeholder="Re-enter passphrase"
                bind:value={exportPassphraseConfirm}
                disabled={exportBusy}
                autocomplete="new-password"
              />
            </div>
            <button
              type="button"
              class="btn btn--primary"
              disabled={!exportReady}
              onclick={handleExport}
            >
              {#if exportBusy}Exporting...{:else}Export and download{/if}
            </button>
            <div class="warn-box">
              <span class="warn-icon">!</span>
              <span>Anyone with both the file and the passphrase can spend from this account. Cawala cannot recover a lost passphrase.</span>
            </div>
          {/if}
        </div>

        <!-- Import -->
        <div class="identity-block">
          <h4 class="identity-heading">Import identity</h4>
          <p class="muted text-sm">
            Paste a bundle below or choose a file. The passphrase must match the one
            used during export.
          </p>
          <div class="field">
            <label class="field-label" for="import-file">Bundle file (optional)</label>
            <input
              id="import-file"
              type="file"
              accept=".json,application/json"
              class="field-input field-input--file"
              onchange={handleImportFile}
              disabled={importBusy}
            />
          </div>
          <div class="field">
            <label class="field-label" for="import-text">Bundle text</label>
            <textarea
              id="import-text"
              class="field-input field-input--textarea"
              placeholder="Paste the exported JSON bundle here"
              rows="4"
              bind:value={importText}
              oninput={runImportPreview}
              disabled={importBusy}
            ></textarea>
          </div>

          {#if importError}
            <p class="text-sm" style="color: var(--danger);">{importError}</p>
          {/if}

          {#if importPreview}
            <div class="preview-box">
              <div class="preview-row">
                <span class="field-label">Incoming node</span>
                <code class="text-sm mono">{importPreview.nodeId}</code>
              </div>
              <div class="preview-row">
                <span class="field-label">Current node</span>
                <code class="text-sm mono">{clientState.endpointId || '(none)'}</code>
              </div>
              {#if importPreview.nodeId === clientState.endpointId}
                <Badge variant="info" label="Same identity" />
              {:else}
                <Badge variant="warn" label="Different identity -- this will replace the current one" />
              {/if}
            </div>
          {/if}

          <div class="field">
            <label class="field-label" for="import-pass">Passphrase</label>
            <input
              id="import-pass"
              type="password"
              class="field-input"
              placeholder="Passphrase used during export"
              bind:value={importPassphrase}
              disabled={importBusy}
              autocomplete="off"
            />
          </div>
          <button
            type="button"
            class="btn btn--primary"
            disabled={!importCanSubmit}
            onclick={handleImportConfirm}
          >
            {#if importBusy}Importing...{:else}Import identity{/if}
          </button>
        </div>

        <!-- Wipe -->
        <div class="identity-block identity-block--danger">
          <h4 class="identity-heading" style="color: var(--danger);">Remove identity from this device</h4>
          <p class="muted text-sm">
            This deletes the identity from this browser. You will lose access to your
            account on this device unless you have exported the identity first.
          </p>
          <button
            type="button"
            class="btn btn--danger-outline"
            disabled={wipeBusy}
            onclick={() => { wipeConfirmOpen = true; }}
          >
            {#if wipeBusy}Removing...{:else}Remove identity{/if}
          </button>
        </div>

        <p class="muted text-xs" style="margin-top: var(--sp-2);">
          Running the same identity on two devices simultaneously is not prevented by the
          app. Use one device at a time to avoid confusing connection behavior.
        </p>
      {/if}
    </div>
  </Card>

  <!-- ── Node Administration ──────────────────────────────────── -->
  <Card title="Node Administration">
    <div class="settings-section">
      <p class="muted text-sm">
        This browser holds a delegated admin key &mdash; never the node operator key or the ledger
        key. Pick which node every admin page is pointed at, then generate a key for any node that
        has not granted you one yet.
      </p>

      <!-- Administered nodes: the same rows as the header selector -->
      <div class="admin-nodes">
        <h4 class="admin-heading">Administered nodes</h4>
        <p class="muted text-xs">
          These are the entries behind the selector at the top of the window. Selecting one
          retargets every admin page.
        </p>
        {#each selectorGroups as group (group.id)}
          {#if group.id !== 'context'}
            <span class="admin-group-label text-xs muted">{group.label}</span>
          {/if}
          {#each group.items as item (item.id)}
            <AdminNodeRow
              {item}
              variant="full"
              onSelect={handleSelectAdmin}
              onRemove={item.isSelf || item.id === 'mock' ? undefined : handleRemoveAdmin}
            />
          {/each}
        {/each}
      </div>

      {#if !mock && valueAdminNodes.length > 0}
        <div class="admin-block">
          <h4 class="admin-heading">Value key protection</h4>
          <p class="muted text-xs">
            A value key must be wrapped with a passphrase (PBKDF2 + AES-GCM) before any value
            action. It adds an unlock step and protects at-rest copies or copied browser profiles,
            but it does not stop in-session XSS while the key is unlocked. Joins and topology keys
            stay plaintext.
          </p>
          {#each valueAdminNodes as node (node.nodeId)}
            <div class="protect-row">
              <span class="text-sm mono">{node.label || `${node.nodeId.slice(0, 12)}…`}</span>
              {#if node.seedProtected}
                <Badge variant="ok" label="Protected" />
                <button
                  type="button"
                  class="btn btn--ghost btn--sm"
                  onclick={() => handleLock(node.nodeId)}
                >
                  Lock now
                </button>
              {:else}
                <button
                  type="button"
                  class="btn btn--ghost btn--sm"
                  onclick={() => openProtect(node.nodeId)}
                >
                  Protect value key
                </button>
              {/if}
            </div>
          {/each}
        </div>
      {/if}

      {#if mock}
        <div class="muted text-sm">
          Generating an admin key needs a live node, so that step is unavailable in mock mode.
          The selection above works either way &mdash; the layout does not change.
        </div>
      {:else}
        <!-- Configure form -->
        <div class="admin-block">
          <h4 class="admin-heading">Generate admin key</h4>
          <div class="field">
            <label class="field-label" for="admin-node-id">Node ID (64 hex characters)</label>
            <input
              id="admin-node-id"
              type="text"
              class="field-input field-input--mono"
              placeholder="e.g. z6Mk..."
              bind:value={configureNodeId}
              disabled={adminBusy}
            />
            {#if configureNodeId && !validateNodeId(configureNodeId)}
              <span class="field-hint field-hint--danger">Must be exactly 64 hex characters.</span>
            {/if}
          </div>
          <div class="field">
            <label class="field-label" for="admin-label">Label (optional)</label>
            <input
              id="admin-label"
              type="text"
              class="field-input"
              placeholder="e.g. office-laptop"
              bind:value={configureLabel}
              disabled={adminBusy}
            />
          </div>
          <div class="field">
            <label class="field-label" for="admin-days">Provisional TTL (days)</label>
            <input
              id="admin-days"
              type="number"
              class="field-input"
              min="1"
              bind:value={configureDays}
              disabled={adminBusy}
            />
            <span class="field-hint">
              Local placeholder only. It sets when this browser stops trying, not when
              the node stops accepting. Import an operator-signed bundle to replace it.
            </span>
          </div>
          <div class="field">
            <label class="field-label" for="admin-node-addr">Target address (optional)</label>
            <input
              id="admin-node-addr"
              type="text"
              class="field-input field-input--mono"
              placeholder="e.g. 0.3.1"
              bind:value={configureNodeAddr}
              disabled={adminBusy}
            />
            {#if configureNodeAddrHint}
              <span class="field-hint field-hint--danger">{configureNodeAddrHint}</span>
            {:else}
              <span class="field-hint">Octal tree address of the administered node. When set, admin calls can reach the node hop-by-hop through the routing tree if a direct connection is not available.</span>
            {/if}
          </div>
          <button
            type="button"
            class="btn btn--primary"
            disabled={!configureReady}
            onclick={handleConfigure}
          >
            {#if adminBusy}Generating...{:else}Generate key{/if}
          </button>
        </div>

        {#if configureResult}
          <div class="admin-result">
            <h4 class="admin-heading">Key generated</h4>
            <p class="muted text-sm">
              Give the public key below to the node operator. They must run the grant
              command on the node before this browser can manage joins.
            </p>
            <div class="admin-pubkey-row">
              <code class="admin-pubkey">{configureResult.adminPubHex}</code>
              <button type="button" class="btn btn--ghost btn--sm" onclick={handleCopyPubKey}>
                Copy
              </button>
            </div>
            <div class="admin-command-row">
              <span class="field-label">Operator command</span>
              <code class="admin-command">
                cawala-node control admin grant --key {configureResult.adminPubHex} --label {configureLabel.trim() || 'browser-admin'}
              </code>
              <button type="button" class="btn btn--ghost btn--sm" onclick={handleCopyCommand}>
                Copy
              </button>
            </div>
            <div class="warn-box">
              <span class="warn-icon">!</span>
              <span>
                The admin private key is stored in this browser. Anyone with browser access can approve
                or reject join requests for the configured node until the key expires or is revoked.
              </span>
            </div>
          </div>
        {/if}

        <!-- Verified grant bundle import -->
        <div class="admin-block">
          <h4 class="admin-heading">Import operator-signed grant</h4>
          <p class="muted text-sm">
            The node operator signs a grant that states your key, its scopes, and its real
            expiry. Paste the bundle here; this browser verifies the signature and uses the
            signed scopes and TTL instead of the provisional ones.
          </p>
          <div class="field">
            <label class="field-label" for="admin-bundle">Bundle link</label>
            <textarea
              id="admin-bundle"
              class="field-input field-input--textarea"
              placeholder="cawala://admin?node=...&grant=..."
              rows="3"
              bind:value={bundleUri}
              disabled={bundleBusy}
            ></textarea>
          </div>
          <button
            type="button"
            class="btn btn--primary"
            disabled={!bundleUri.trim() || bundleBusy}
            onclick={handleApplyBundle}
          >
            {#if bundleBusy}Importing...{:else}Import bundle{/if}
          </button>
          {#if bundleMessage}
            <p
              class="text-sm"
              style="color: {bundleMessage.kind === 'ok' ? 'var(--ok)' : 'var(--danger)'};"
            >
              {bundleMessage.text}
            </p>
          {/if}
        </div>
      {/if}
    </div>
  </Card>

  <!-- Import confirm dialog -->
  <ConfirmDialog
    open={importConfirmOpen}
    title="Replace identity?"
    message="This will replace the identity on this device. Make sure you have already exported the current identity if you still need it. The page will reload after import."
    confirmLabel="Replace and reload"
    variant="danger"
    onConfirm={doImport}
    onCancel={() => { importConfirmOpen = false; }}
  />

  <!-- Wipe confirm dialog -->
  <ConfirmDialog
    open={wipeConfirmOpen}
    title="Remove identity?"
    message="This removes the identity from this device. You will not be able to access your account here unless you have already exported it. The page will reload after removal."
    confirmLabel="Remove and reload"
    variant="danger"
    onConfirm={doWipe}
    onCancel={() => { wipeConfirmOpen = false; }}
  />

  <!-- Remove admin confirm dialog -->
  <ConfirmDialog
    open={removeConfirmOpen}
    title="Remove admin node?"
    message="This will remove the admin key for this node from this browser. You will not be able to manage join requests for this node unless you reconfigure."
    confirmLabel="Remove"
    variant="danger"
    onConfirm={doRemoveAdmin}
    onCancel={() => { removeConfirmOpen = false; removeTarget = null; }}
  />

  <!-- Value-key protection dialog -->
  <UnlockAdminKeyDialog
    open={protectDialog !== null}
    title="Protect value key"
    message="Choose a passphrase to wrap this value key. It is used locally to unwrap the key and is never sent anywhere. There is no recovery: if you forget it, remove and re-generate the key."
    confirmLabel="Protect"
    busy={protectBusy}
    error={protectError}
    requireConfirm={true}
    onSubmit={handleProtectSubmit}
    onCancel={() => { protectDialog = null; protectError = null; }}
  />

  <Card title="Location Service">
    <div class="settings-section">
      <p class="muted text-sm">
        An optional companion service that suggests an octal address based on your geographic region. This is a separate, external service &mdash; not required to use Cawala. Your parent node assigns the final address regardless.
      </p>
      <div class="setting-row" style="margin-top: var(--sp-3);">
        <span class="setting-label">Service</span>
        <code class="text-sm">location.cawala.net</code>
      </div>
      <div class="setting-row">
        <span class="setting-label">Status</span>
        {#if isMockMode()}
          <span class="text-sm muted">Mock mode (not connected)</span>
        {:else}
          <span class="text-sm muted">Not available in the web client</span>
        {/if}
      </div>
    </div>
  </Card>

  <Card title="About">
    <div class="settings-section">
      <div class="setting-row">
        <span class="setting-label">Version</span>
        <span class="text-sm">Cawala M4</span>
      </div>
      <div class="setting-row">
        <span class="setting-label">WASM</span>
        <span class="text-sm">{isMockMode() ? 'Not loaded (mock mode)' : 'Loaded'}</span>
      </div>
    </div>
  </Card>
</div>

<style>
  .settings-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-5);
  }
  .settings-section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .setting-row {
    display: flex;
    align-items: center;
    gap: var(--sp-4);
  }
  .setting-label {
    min-width: 120px;
    font-size: var(--text-sm);
    font-weight: 500;
    color: var(--muted);
  }
  .persistence-warn {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }
  .text-sm { font-size: var(--text-sm); }
  .text-xs { font-size: var(--text-xs); }
  .mono { font-family: var(--mono); }
  .muted { color: var(--muted); }

  /* ── Buttons ─────────────────────────────────── */
  .btn {
    padding: var(--sp-2) var(--sp-3);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease),
                opacity var(--duration-fast) var(--ease);
  }
  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .btn--danger-outline {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .btn--danger-outline:hover:not(:disabled) {
    background: var(--danger-dim);
  }

  /* ── Identity blocks ─────────────────────────── */
  .identity-block {
    padding: var(--sp-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .identity-block--danger {
    border-color: color-mix(in srgb, var(--danger) 30%, var(--border));
  }
  .identity-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }

  /* ── Fields ──────────────────────────────────── */
  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .field-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .field-input {
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg);
    color: var(--fg);
    font: inherit;
    font-size: var(--text-sm);
    font-family: var(--mono);
    transition: border-color var(--duration-fast) var(--ease);
  }
  .field-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .field-input::placeholder {
    color: var(--muted);
    opacity: 0.6;
  }
  .field-input:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .field-input--file {
    padding: var(--sp-1) var(--sp-2);
    font-family: var(--sans);
  }
  .field-input--textarea {
    resize: vertical;
    min-height: 80px;
  }

  /* ── Warning box ─────────────────────────────── */
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

  /* ── Preview box ─────────────────────────────── */
  .preview-box {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .preview-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
  }
  .preview-row code {
    word-break: break-all;
  }

  /* ── Admin card ───────────────────────────────── */
  .admin-block {
    padding: var(--sp-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .admin-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
    margin: 0;
  }
  .field-hint {
    font-size: var(--text-xs);
    color: var(--muted);
    margin-top: calc(-1 * var(--sp-1));
  }
  .field-hint--danger {
    color: var(--danger);
  }
  .field-input--mono {
    font-family: var(--mono);
    font-size: var(--text-xs);
  }
  .admin-result {
    padding: var(--sp-4);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    background: var(--bg);
  }
  .admin-pubkey-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .admin-pubkey {
    flex: 1;
    font-family: var(--mono);
    font-size: var(--text-xs);
    word-break: break-all;
    color: var(--accent);
  }
  .admin-command-row {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }
  .admin-command {
    padding: var(--sp-3);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    font-family: var(--mono);
    font-size: var(--text-xs);
    word-break: break-all;
    color: var(--fg);
  }
  .btn--sm {
    padding: var(--sp-1) var(--sp-2);
    font-size: var(--text-xs);
  }
  .btn--ghost {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
  }
  .btn--ghost:hover {
    background: var(--bg-hover);
    color: var(--fg);
  }
  .admin-nodes {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }
  .admin-group-label {
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .protect-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    flex-wrap: wrap;
  }
</style>
