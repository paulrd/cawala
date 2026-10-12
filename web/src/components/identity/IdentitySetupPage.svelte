<script>
  import { onMount, tick } from 'svelte';
  import Card from '../shared/Card.svelte';
  import ConfirmDialog from '../shared/ConfirmDialog.svelte';
  import MnemonicPhrase from './MnemonicPhrase.svelte';
  import EthAddressBlock from './EthAddressBlock.svelte';
  import PasskeyPanel from './PasskeyPanel.svelte';
  import {
    generateMnemonic,
    validateMnemonic,
    previewIdentity,
    createIdentity,
    restoreIdentity,
    rotateUserEthIdentity,
    isPasskeyAvailable,
    InvalidMnemonicError,
  } from '../../lib/api.js';
  import { userIdentityState, showToast } from '../../lib/stores.svelte.js';
  import { navigate } from '../../lib/router.svelte.js';
  import { ROUTES } from '../../lib/constants.js';

  /**
   * IdentitySetupPage — create / restore / manage the user identity
   * (BIP-39 mnemonic → ETH address, spec §1.1).
   *
   * One route (`#/identity`), one step machine:
   *   intro → create-words → create-confirm → create-done
   *        ↘ restore-form → restore-done
   *   established on arrival → manage → rotate-form
   *
   * The recovery phrase is shown exactly once, behind a deliberate reveal,
   * and the create flow cannot finish until the user ticks a written-down
   * checkbox and types three words back.
   */

  const STEPS = [
    { key: 'create-words', label: 'Write down' },
    { key: 'create-confirm', label: 'Confirm' },
    { key: 'create-done', label: 'Address' },
  ];

  let step = $state(userIdentityState.established ? 'manage' : 'intro');

  // ── Create flow ─────────────────────────────────────────────
  let phrase = $state(''); // generated mnemonic, shown once
  let revealed = $state(false);
  let backedUp = $state(false);
  let confirmIndices = $state([]); // word indices (0-based) asked back
  let confirmInputs = $state(['', '', '']);
  let busy = $state(false);
  let stepError = $state(null);

  // ── Restore flow ────────────────────────────────────────────
  let restoreText = $state('');
  let restorePassphrase = $state('');
  let showPassphrase = $state(false);
  let validation = $state(null); // validateMnemonic result | null
  let validating = $state(false);
  let previewAddress = $state(null);
  let restoreConfirmOpen = $state(false);

  // ── Rotate flow (manage → rotate-form) ─────────────────────
  let rotateSource = $state('enter'); // 'enter' | 'generate'
  let rotateText = $state('');
  let rotatePassphrase = $state('');
  let showRotatePassphrase = $state(false);
  let rotateRevealed = $state(false); // a generated phrase is shown once, on purpose
  let rotateBackedUp = $state(false); // "I wrote the new phrase down"
  let rotateGenError = $state(null);
  let rotateValidation = $state(null);
  let rotateValidating = $state(false);
  let rotatePreviewAddress = $state(null);
  let rotateConfirmOpen = $state(false);
  let rotateError = $state(null);
  let rotating = $state(false);
  let rotateDone = $state(false); // success note shown on the manage step

  let passkeyAvailable = $derived(isPasskeyAvailable());
  let phraseWords = $derived(phrase ? phrase.split(' ') : []);
  let restoreWordCount = $derived(
    restoreText.trim() === '' ? 0 : restoreText.trim().split(/\s+/).length,
  );
  let restoreValid = $derived(validation?.ok === true);
  let restoreInvalid = $derived(validation != null && !validation.ok && validation.error.code !== 'empty');
  let canFinishCreate = $derived(
    revealed && backedUp && phraseWords.length > 0 && confirmInputs.every((v, i) => matchesConfirm(i, v)),
  );

  let rotateWordCount = $derived(
    rotateText.trim() === '' ? 0 : rotateText.trim().split(/\s+/).length,
  );
  let rotateValid = $derived(rotateValidation?.ok === true);
  let rotateInvalid = $derived(
    rotateValidation != null && !rotateValidation.ok && rotateValidation.error.code !== 'empty',
  );
  let rotateWords = $derived(rotateText.trim() === '' ? [] : rotateText.trim().split(/\s+/));
  let rotateReady = $derived(rotateValid && rotatePreviewAddress != null);
  // The write-down checkbox only exists once there is something to write down.
  let rotateAckVisible = $derived(rotateSource === 'enter' || rotateRevealed);
  let canRotate = $derived(rotateReady && rotateBackedUp && !rotating);
  let rotateNeedsAck = $derived(rotateReady && rotateAckVisible && !rotateBackedUp);

  let stepEl = $state(null);
  // Where the generic step-focus should land instead of the container
  // (consumed by the effect below; deliberately not reactive).
  let pendingFocus = null;
  // Which step the restore form's Back button returns to.
  let restoreFrom = 'intro';

  // Move focus to the step's focus target whenever the step changes, so
  // keyboard and screen-reader users land on the new content.
  $effect(() => {
    void step;
    const target = pendingFocus;
    pendingFocus = null;
    tick().then(() => {
      const el = target ? document.getElementById(target) : null;
      (el ?? stepEl)?.focus();
    });
  });

  // Live validation + address preview while typing the restore phrase
  // (debounced; cancelled when the input changes again).
  $effect(() => {
    const text = restoreText;
    const passphrase = restorePassphrase;
    validation = null;
    previewAddress = null;
    if (text.trim() === '') return undefined;
    let cancelled = false;
    validating = true;
    const timer = setTimeout(async () => {
      const result = await validateMnemonic(text);
      if (cancelled) return;
      validation = result;
      validating = false;
      if (result.ok) {
        try {
          const preview = await previewIdentity(result.normalized, passphrase);
          if (!cancelled) previewAddress = preview.address;
        } catch {
          if (!cancelled) previewAddress = null;
        }
      }
    }, 280);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      validating = false;
    };
  });

  // Live validation + address preview for the new rotation phrase (debounced).
  $effect(() => {
    const text = rotateText;
    const passphrase = rotatePassphrase;
    rotateValidation = null;
    rotatePreviewAddress = null;
    if (text.trim() === '') return undefined;
    let cancelled = false;
    rotateValidating = true;
    const timer = setTimeout(async () => {
      const result = await validateMnemonic(text);
      if (cancelled) return;
      rotateValidation = result;
      rotateValidating = false;
      if (result.ok) {
        try {
          const preview = await previewIdentity(result.normalized, passphrase);
          if (!cancelled) rotatePreviewAddress = preview.address;
        } catch {
          if (!cancelled) rotatePreviewAddress = null;
        }
      }
    }, 280);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      rotateValidating = false;
    };
  });

  onMount(() => {
    if (userIdentityState.established) step = 'manage';
  });

  // ── Navigation between steps ────────────────────────────────

  function startCreate() {
    phrase = '';
    revealed = false;
    backedUp = false;
    confirmInputs = ['', '', ''];
    stepError = null;
    step = 'create-words';
    void makePhrase();
  }

  async function makePhrase() {
    try {
      phrase = await generateMnemonic();
    } catch (err) {
      stepError = err?.message || 'Could not generate a recovery phrase. Try again.';
    }
  }

  function goBackToIntro() {
    // Drop the generated phrase: nothing was created yet.
    phrase = '';
    revealed = false;
    backedUp = false;
    stepError = null;
    step = 'intro';
  }

  function beginConfirm() {
    // Ask back three words at random, in phrase order.
    const pool = [...Array(phraseWords.length).keys()];
    for (let i = pool.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    confirmIndices = pool.slice(0, 3).sort((a, b) => a - b);
    confirmInputs = ['', '', ''];
    stepError = null;
    pendingFocus = 'confirm-0';
    step = 'create-confirm';
  }

  function backToWords() {
    stepError = null;
    step = 'create-words';
  }

  function matchesConfirm(slot, value) {
    const index = confirmIndices[slot];
    if (index == null || !phraseWords[index]) return false;
    return value.trim().toLowerCase() === phraseWords[index];
  }

  async function finishCreate() {
    if (!canFinishCreate) return;
    busy = true;
    stepError = null;
    try {
      await createIdentity({ mnemonic: phrase });
      step = 'create-done';
      showToast('Identity created. Your account address is ready.', 'ok');
    } catch (err) {
      stepError = err?.message || 'Could not create the identity. Nothing was saved — try again.';
    } finally {
      busy = false;
    }
  }

  // ── Restore ─────────────────────────────────────────────────

  function startRestore(from = 'intro') {
    restoreFrom = from;
    restoreText = '';
    restorePassphrase = '';
    showPassphrase = false;
    validation = null;
    previewAddress = null;
    stepError = null;
    pendingFocus = 'restore-phrase';
    step = 'restore-form';
  }

  async function doRestore() {
    restoreConfirmOpen = false;
    if (!restoreValid || !previewAddress) return;
    busy = true;
    stepError = null;
    try {
      await restoreIdentity(validation.normalized, restorePassphrase);
      step = 'restore-done';
      showToast('Identity restored.', 'ok');
    } catch (err) {
      if (err instanceof InvalidMnemonicError) {
        stepError = err.message;
      } else {
        stepError = err?.message || 'Could not restore the identity. Nothing was saved.';
      }
    } finally {
      busy = false;
    }
  }

  function manageRestoreAnother() {
    startRestore('manage');
  }

  // ── Rotate (manage → rotate-form) ──────────────────────────

  function resetRotateForm() {
    rotateSource = 'enter';
    rotateText = '';
    rotatePassphrase = '';
    showRotatePassphrase = false;
    rotateRevealed = false;
    rotateBackedUp = false;
    rotateGenError = null;
    rotateValidation = null;
    rotatePreviewAddress = null;
    rotateError = null;
  }

  function startRotate() {
    resetRotateForm();
    pendingFocus = 'rotate-phrase';
    step = 'rotate-form';
  }

  function leaveRotate() {
    resetRotateForm();
    step = 'manage';
  }

  // Swap where the new phrase comes from. Each source starts from a clean
  // slate so a phrase typed for one path can't silently carry into the other.
  async function setRotateSource(source) {
    if (source === rotateSource || rotating) return;
    rotateSource = source;
    rotateBackedUp = false;
    rotateRevealed = false;
    rotateError = null;
    if (source === 'enter') {
      rotateText = '';
      rotatePassphrase = '';
      showRotatePassphrase = false;
      rotateGenError = null;
      await tick();
      document.getElementById('rotate-phrase')?.focus();
    } else {
      void makeRotatePhrase();
      await tick();
      document.getElementById('rotate-generated')?.focus();
    }
  }

  // A fresh 12-word phrase for the generate path: revealed deliberately,
  // never persisted until the network accepts the rotation.
  async function makeRotatePhrase() {
    rotateGenError = null;
    rotateText = '';
    rotateRevealed = false;
    rotateBackedUp = false;
    try {
      rotateText = await generateMnemonic();
    } catch (err) {
      rotateGenError = err?.message || 'Could not generate a recovery phrase. Try again.';
    }
  }

  async function doRotate() {
    rotateConfirmOpen = false;
    if (!canRotate) return;
    rotating = true;
    rotateError = null;
    try {
      const result = await rotateUserEthIdentity(rotateValidation.normalized, rotatePassphrase);
      if (result.status === 'accepted') {
        rotateDone = true;
        leaveRotate();
        showToast('Identity rotated. Your account now uses the new phrase and address.', 'ok');
      } else if (result.status === 'unsupported') {
        rotateError =
          'This network node does not support rotating an account identity yet. Your current identity is unchanged.';
      } else {
        rotateError =
          `The network did not accept the rotation (${result.status}). Your current identity is unchanged.`;
      }
    } catch (err) {
      rotateError =
        err?.message || 'Could not rotate the identity. Your current identity is unchanged.';
    } finally {
      rotating = false;
    }
  }
</script>

<div class="identity-page">
  <div class="page-top">
    <button type="button" class="back-link" onclick={() => navigate(ROUTES.SETTINGS)}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
      Back to settings
    </button>
  </div>

  {#key step}
    <div class="identity-step" bind:this={stepEl} tabindex="-1">
      <!-- ── Intro: choose a path ─────────────────────────────── -->
      {#if step === 'intro'}
        <Card title="Your identity">
          <div class="stack">
            <h3 class="step-heading">One phrase, one address</h3>
            <p class="body-text">
              Your Cawala identity is a 12-word recovery phrase. It produces your
              account address (the <span class="mono-inline">0x…</span> code other
              people send things to) and the keys this browser signs with. Keep
              that phrase safe and the identity is yours on any device, forever.
            </p>

            <div class="choice-grid">
              <button type="button" class="tile" onclick={startCreate}>
                <span class="tile-icon" aria-hidden="true">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                </span>
                <span class="tile-title">Create a new identity</span>
                <span class="tile-desc">We’ll make a fresh 12-word phrase for you to write down.</span>
              </button>
              <button type="button" class="tile" onclick={startRestore}>
                <span class="tile-icon" aria-hidden="true">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </span>
                <span class="tile-title">Restore a phrase I already have</span>
                <span class="tile-desc">Type in a phrase from another device or from paper.</span>
              </button>
            </div>

            <div class="primer">
              <div class="primer-row">
                <span class="primer-num">1</span>
                <p>
                  <strong>The phrase is the account.</strong> Write it down somewhere
                  only you can reach. Nobody can reset it for you — lose it with this
                  device and the identity is gone for good.
                </p>
              </div>
              <div class="primer-row">
                <span class="primer-num">2</span>
                <p>
                  <strong>A passkey is a shortcut.</strong> After setup you can unlock
                  with your fingerprint or face on this device — handy, but it never
                  replaces the written phrase.
                </p>
              </div>
            </div>
          </div>
        </Card>

      <!-- ── Create step 1: show + write down ─────────────────── -->
      {:else if step === 'create-words'}
        <Card title="Step 1 · Write it down">
          <div class="stack">
            {@render stepRail(0)}

            <h3 class="step-heading">Your 12-word recovery phrase</h3>
            <p class="body-text">
              These words are your account. Write them in this order — on paper, or
              somewhere only you can reach. Order matters, and so does every letter.
            </p>

            {#if phraseWords.length > 0}
              <MnemonicPhrase
                words={phraseWords}
                {revealed}
                onReveal={() => (revealed = true)}
              />
            {:else if stepError}
              <p class="field-error" role="alert">{stepError}</p>
              <button type="button" class="btn btn--ghost" onclick={() => { stepError = null; void makePhrase(); }}>
                Try again
              </button>
            {:else}
              <div class="generating" aria-live="polite">
                <span class="spinner" aria-hidden="true"></span>
                <span class="text-sm muted">Making a fresh phrase…</span>
              </div>
            {/if}

            {#if revealed}
              <div class="warn-box">
                <span class="warn-icon" aria-hidden="true">!</span>
                <span>
                  Anyone who has these words can use your account. Don’t share them,
                  don’t photograph them for anyone else, and never type them into a
                  site you don’t trust — Cawala will never ask you for them.
                </span>
              </div>

              <label class="check-row">
                <input type="checkbox" bind:checked={backedUp} />
                <span>I’ve written these 12 words down and stored them somewhere safe.</span>
              </label>
            {/if}

            <div class="actions">
              <button type="button" class="btn btn--ghost" onclick={goBackToIntro}>
                Start over
              </button>
              <button
                type="button"
                class="btn btn--primary"
                disabled={!revealed || !backedUp || phraseWords.length === 0}
                onclick={beginConfirm}
              >
                Continue
              </button>
            </div>
            {#if revealed && !backedUp}
              <p class="hint text-xs muted">Tick the box once your words are written down.</p>
            {/if}
          </div>
        </Card>

      <!-- ── Create step 2: confirm the backup ────────────────── -->
      {:else if step === 'create-confirm'}
        <Card title="Step 2 · Confirm your backup">
          <div class="stack">
            {@render stepRail(1)}

            <h3 class="step-heading">Type three words back</h3>
            <p class="body-text">
              Pick up your written copy and type the words we ask for. This only
              checks that what you wrote is readable — nothing is sent anywhere.
            </p>

            <div class="confirm-grid">
              {#each confirmIndices as wordIndex, slot (slot)}
                {@const filled = confirmInputs[slot]?.trim() !== ''}
                {@const correct = matchesConfirm(slot, confirmInputs[slot] ?? '')}
                <div class="confirm-field" class:confirm-field--ok={correct}>
                  <label class="field-label" for="confirm-{slot}">Word {wordIndex + 1}</label>
                  <div class="confirm-input-wrap">
                    <input
                      id="confirm-{slot}"
                      type="text"
                      class="field-input"
                      class:field-input--bad={filled && !correct}
                      autocomplete="off"
                      autocapitalize="none"
                      spellcheck="false"
                      bind:value={confirmInputs[slot]}
                    />
                    {#if correct}
                      <span class="confirm-mark confirm-mark--ok" aria-hidden="true">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
                      </span>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>

            {#if confirmInputs.some((v, i) => v.trim() !== '' && !matchesConfirm(i, v))}
              <p class="field-error" role="alert">
                One or more words don’t match. Check your written copy — all words are
                lowercase, no numbers, in the original order.
              </p>
            {/if}

            {#if stepError}
              <p class="field-error" role="alert">{stepError}</p>
            {/if}

            <div class="actions">
              <button type="button" class="btn btn--ghost" onclick={backToWords} disabled={busy}>
                Back to my words
              </button>
              <button type="button" class="btn btn--primary" disabled={!canFinishCreate || busy} onclick={finishCreate}>
                {#if busy}Finishing…{:else}Finish setup{/if}
              </button>
            </div>
          </div>
        </Card>

      <!-- ── Create step 3 / restore done: the address ────────── -->
      {:else if step === 'create-done' || step === 'restore-done'}
        <Card title={step === 'create-done' ? 'Step 3 · Your address' : 'Identity restored'}>
          <div class="stack">
            {#if step === 'create-done'}
              {@render stepRail(2)}
            {/if}

            <div class="done-hero" aria-live="polite">
              <span class="done-icon" aria-hidden="true">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                  <path d="M22 4L12 14.01l-3-3"/>
                </svg>
              </span>
              <h3 class="step-heading">
                {step === 'create-done' ? 'Your identity is ready' : 'Identity restored'}
              </h3>
              <p class="body-text muted-text">
                {step === 'create-done'
                  ? 'Same phrase, same address, on any device. This is yours now.'
                  : 'Your phrase gave back the same identity — the address below is the account it unlocks.'}
              </p>
            </div>

            <EthAddressBlock
              address={userIdentityState.address}
              explanation="Share it like an account number: it identifies you, and knowing it can’t take anything from you."
            />

            {#if passkeyAvailable}
              <PasskeyPanel />
            {/if}

            <div class="warn-box">
              <span class="warn-icon" aria-hidden="true">!</span>
              <span>
                Your recovery phrase is the only way to recover this account. A passkey
                unlocks it on this device, nothing more. Lose both, and nobody — not
                Cawala, not support — can bring it back.
              </span>
            </div>

            <div class="actions actions--end">
              <button type="button" class="btn btn--primary" onclick={() => navigate(ROUTES.SETTINGS)}>
                Go to settings
              </button>
            </div>
          </div>
        </Card>

      <!-- ── Restore: the form ────────────────────────────────── -->
      {:else if step === 'restore-form'}
        <Card title="Restore identity">
          <div class="stack">
            <h3 class="step-heading">Restore from your recovery phrase</h3>
            <p class="body-text">
              Type the phrase you wrote down. We check it first and show you the
              address it gives — nothing on this device changes until you confirm.
            </p>

            <div class="field">
              <label class="field-label" for="restore-phrase">Recovery phrase</label>
              <textarea
                id="restore-phrase"
                class="field-input field-input--textarea"
                class:field-input--bad={restoreInvalid}
                rows="3"
                placeholder="Type or paste your words, separated by spaces"
                bind:value={restoreText}
                autocomplete="off"
                autocapitalize="none"
                spellcheck="false"
                disabled={busy}
              ></textarea>
              <div class="field-meta">
                <span class="text-xs muted">
                  {#if restoreWordCount === 0}
                    12, 15, 18, 21 or 24 words
                  {:else}
                    {restoreWordCount} {restoreWordCount === 1 ? 'word' : 'words'}
                  {/if}
                </span>
                {#if validating}
                  <span class="text-xs muted">Checking…</span>
                {:else if restoreValid}
                  <span class="field-ok text-xs">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
                    Phrase checks out
                  </span>
                {/if}
              </div>
              {#if restoreInvalid && validation?.error}
                <p class="field-error" role="alert">{validation.error.message}</p>
              {/if}
            </div>

            {#if !showPassphrase}
              <button
                type="button"
                class="link-btn"
                onclick={() => (showPassphrase = true)}
              >
                Passphrase (optional) — add if you used one
              </button>
            {:else}
              <div class="field">
                <label class="field-label" for="restore-passphrase">Passphrase</label>
                <input
                  id="restore-passphrase"
                  type="password"
                  class="field-input"
                  placeholder="Leave empty if you never set one"
                  bind:value={restorePassphrase}
                  autocomplete="off"
                  disabled={busy}
                />
                <p class="text-xs muted field-help">
                  A passphrase is extra text mixed into the phrase when the identity
                  was made. If you didn’t use one, leave it empty. If you did, it must
                  match exactly — the same words with a different passphrase are a
                  different account, and nothing tells the two apart.
                </p>
              </div>
            {/if}

            {#if restoreValid && previewAddress}
              <div class="preview-panel">
                <span class="field-label">This phrase gives</span>
                <EthAddressBlock
                  address={previewAddress}
                  explanation="Restore only if this is the address you expect. A different address means the words or the passphrase aren’t the ones this account was made with."
                  animate={false}
                />
              </div>
            {/if}

            {#if stepError}
              <p class="field-error" role="alert">{stepError}</p>
            {/if}

            <div class="actions">
              <button type="button" class="btn btn--ghost" onclick={() => (step = restoreFrom)} disabled={busy}>
                Back
              </button>
              <button
                type="button"
                class="btn btn--primary"
                disabled={!restoreValid || previewAddress == null || busy}
                onclick={() => (restoreConfirmOpen = true)}
              >
                Restore identity
              </button>
            </div>
          </div>
        </Card>

      <!-- ── Rotate: its own surface, reached from manage ──────── -->
      {:else if step === 'rotate-form'}
        <Card title="Rotate identity">
          <div class="stack">
            <h3 class="step-heading">Switch this account to a new phrase</h3>
            <p class="body-text">
              Your current phrase signs for the change, so nothing moves until the
              network accepts it. If the network refuses, your identity stays exactly
              as it is.
            </p>

            <div class="warn-box">
              <span class="warn-icon" aria-hidden="true">!</span>
              <span>
                This is a one-way change. Once the network accepts it, your current
                phrase stops controlling this account and cannot be used to get it
                back — the new phrase becomes the only way to recover the account,
                and your address changes to the one the new phrase gives.
              </span>
            </div>

            <div class="source-grid" role="group" aria-label="Where the new phrase comes from">
              <button
                type="button"
                class="source-tile"
                class:source-tile--on={rotateSource === 'enter'}
                aria-pressed={rotateSource === 'enter'}
                disabled={rotating}
                onclick={() => setRotateSource('enter')}
              >
                {#if rotateSource === 'enter'}
                  <span class="source-check" aria-hidden="true">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                  </span>
                {/if}
                <span class="source-title">Enter a phrase I already have</span>
                <span class="source-desc">Type in words you wrote down somewhere safe.</span>
              </button>
              <button
                type="button"
                class="source-tile"
                class:source-tile--on={rotateSource === 'generate'}
                aria-pressed={rotateSource === 'generate'}
                disabled={rotating}
                onclick={() => setRotateSource('generate')}
              >
                {#if rotateSource === 'generate'}
                  <span class="source-check" aria-hidden="true">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                  </span>
                {/if}
                <span class="source-title">Generate a fresh phrase</span>
                <span class="source-desc">We make 12 new words for you to write down first.</span>
              </button>
            </div>

            {#if rotateSource === 'enter'}
              <div class="field">
                <label class="field-label" for="rotate-phrase">New recovery phrase</label>
                <textarea
                  id="rotate-phrase"
                  class="field-input field-input--textarea"
                  class:field-input--bad={rotateInvalid}
                  rows="3"
                  placeholder="Type or paste your new words, separated by spaces"
                  bind:value={rotateText}
                  autocomplete="off"
                  autocapitalize="none"
                  spellcheck="false"
                  disabled={rotating}
                ></textarea>
                <div class="field-meta">
                  <span class="text-xs muted">
                    {#if rotateWordCount === 0}
                      12, 15, 18, 21 or 24 words
                    {:else}
                      {rotateWordCount} {rotateWordCount === 1 ? 'word' : 'words'}
                    {/if}
                  </span>
                  {#if rotateValidating}
                    <span class="text-xs muted">Checking…</span>
                  {:else if rotateValid}
                    <span class="field-ok text-xs">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
                      Phrase checks out
                    </span>
                  {/if}
                </div>
                {#if rotateInvalid && rotateValidation?.error}
                  <p class="field-error" role="alert">{rotateValidation.error.message}</p>
                {/if}
              </div>

              {#if !showRotatePassphrase}
                <button
                  type="button"
                  class="link-btn"
                  onclick={() => (showRotatePassphrase = true)}
                >
                  Passphrase (optional) — add if you used one
                </button>
              {:else}
                <div class="field">
                  <label class="field-label" for="rotate-passphrase">Passphrase</label>
                  <input
                    id="rotate-passphrase"
                    type="password"
                    class="field-input"
                    placeholder="Leave empty if you never set one"
                    bind:value={rotatePassphrase}
                    autocomplete="off"
                    disabled={rotating}
                  />
                  <p class="text-xs muted field-help">
                    The same words with a different passphrase are a different
                    account. Leave this empty if you never set one.
                  </p>
                </div>
              {/if}
            {:else}
              <div class="rotate-generated" id="rotate-generated" tabindex="-1">
                <span class="field-label">Your new recovery phrase</span>
                {#if rotateGenError}
                  <p class="field-error" role="alert">{rotateGenError}</p>
                  <button type="button" class="btn btn--ghost" onclick={() => void makeRotatePhrase()}>
                    Try again
                  </button>
                {:else if rotateWords.length === 0}
                  <div class="generating" aria-live="polite">
                    <span class="spinner" aria-hidden="true"></span>
                    <span class="text-sm muted">Making a fresh phrase…</span>
                  </div>
                {:else}
                  <MnemonicPhrase
                    words={rotateWords}
                    revealed={rotateRevealed}
                    onReveal={() => (rotateRevealed = true)}
                  />
                  {#if !rotateRevealed}
                    <button type="button" class="link-btn" onclick={() => void makeRotatePhrase()}>
                      Make a different phrase
                    </button>
                  {/if}
                {/if}
              </div>
            {/if}

            {#if rotateReady}
              <div class="preview-panel">
                <span class="field-label">The new phrase gives</span>
                <EthAddressBlock
                  address={rotatePreviewAddress}
                  explanation="This becomes your account address once the network accepts the rotation. Share it with anyone who sends to you."
                  animate={false}
                />
              </div>
            {/if}

            {#if rotateAckVisible}
              <label class="check-row">
                <input type="checkbox" bind:checked={rotateBackedUp} disabled={rotating} />
                <span>
                  {#if rotateSource === 'generate'}
                    I’ve written these 12 words down and stored them somewhere safe.
                  {:else}
                    I’ve written this phrase down somewhere safe — after the rotation
                    it is the only way back into this account.
                  {/if}
                </span>
              </label>
            {/if}

            {#if rotateError}
              <p class="field-error" role="alert">{rotateError}</p>
            {/if}

            <div class="actions">
              <button type="button" class="btn btn--ghost" onclick={leaveRotate} disabled={rotating}>
                Back
              </button>
              <button
                type="button"
                class="btn btn--danger-outline"
                disabled={!canRotate}
                onclick={() => (rotateConfirmOpen = true)}
              >
                {#if rotating}Rotating…{:else}Rotate identity{/if}
              </button>
            </div>
            {#if rotateNeedsAck}
              <p class="hint text-xs muted">Tick the box above to continue.</p>
            {/if}
          </div>
        </Card>

      <!-- ── Manage: already established ──────────────────────── -->
      {:else if step === 'manage'}
        <Card title="Your identity">
          <div class="stack">
            <h3 class="step-heading">Your account identity</h3>

            <EthAddressBlock
              address={userIdentityState.address}
              explanation="This address comes from your recovery phrase. Share it like an account number — knowing it lets people send you things, not take them."
              animate={false}
            />

            <div class="setting-row">
              <span class="setting-label">Recovery phrase</span>
              <span class="text-sm muted">
                {userIdentityState.source === 'restored' ? 'Restored' : 'Created'} here
                {#if userIdentityState.createdAt}
                  on {new Date(userIdentityState.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                {/if}
              </span>
            </div>

            {#if rotateDone}
              <p class="rotate-done" role="status">
                Rotated. Your account now uses the new phrase, and the address above
                is the one to share from now on.
              </p>
            {/if}

            <div class="rotate-block">
              <div class="rotate-head">
                <span class="rotate-icon" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="23 4 23 10 17 10" />
                    <polyline points="1 20 1 14 7 14" />
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
                    <path d="M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                  </svg>
                </span>
                <div class="rotate-head-text">
                  <h4 class="rotate-heading">Rotate to a new recovery phrase</h4>
                  <p class="rotate-desc text-xs muted">
                    Switches the account to a new phrase — and to the address that
                    phrase gives. Your current phrase signs for the change; once the
                    network accepts it, that phrase stops controlling the account and
                    cannot be used to get it back. Restoring a different phrase,
                    below, replaces the identity stored on this device instead.
                  </p>
                </div>
              </div>
              <button type="button" class="btn btn--danger-outline" onclick={startRotate}>
                Rotate to a new phrase
              </button>
            </div>

            {#if passkeyAvailable}
              <PasskeyPanel />
            {/if}

            <div class="warn-box">
              <span class="warn-icon" aria-hidden="true">!</span>
              <span>
                Keep your recovery phrase where you can find it but others can’t.
                It is the only way back into this account — a passkey only opens
                the door on this device.
              </span>
            </div>

            <div class="actions">
              <button type="button" class="btn btn--ghost" onclick={() => navigate(ROUTES.SETTINGS)}>
                Back to settings
              </button>
              <button type="button" class="btn btn--danger-outline" onclick={manageRestoreAnother}>
                Restore a different phrase
              </button>
            </div>
          </div>
        </Card>
      {/if}
    </div>
  {/key}
</div>

<!-- Restore replaces whatever identity is on this device: one explicit confirm. -->
<ConfirmDialog
  open={restoreConfirmOpen}
  title="Replace the identity on this device?"
  message="Restoring puts this phrase in charge of this device’s identity. The address it gives must be the one you expect — continue only if you mean to switch."
  confirmLabel="Restore identity"
  variant="danger"
  onConfirm={doRestore}
  onCancel={() => (restoreConfirmOpen = false)}
/>

<!-- Rotation switches which phrase controls the account — and with it the
     address: one explicit confirm, showing exactly what changes. -->
<ConfirmDialog
  open={rotateConfirmOpen}
  title="Rotate to this new phrase?"
  message="Your current phrase signs for this change. Once the network accepts it, that phrase stops controlling this account and cannot take it back — the new phrase becomes the only way to recover it. Your address becomes the one below, so share it with anyone who sends to you. If the network refuses, nothing changes."
  confirmLabel="Rotate identity"
  variant="danger"
  onConfirm={doRotate}
  onCancel={() => (rotateConfirmOpen = false)}
>
  <div class="rotate-diff">
    <div class="diff-part">
      <span class="diff-label">Current address</span>
      <span class="diff-value">{userIdentityState.address}</span>
    </div>
    <span class="diff-arrow" aria-hidden="true">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>
    </span>
    <div class="diff-part diff-part--next">
      <span class="diff-label">New address</span>
      <span class="diff-value">{rotatePreviewAddress}</span>
    </div>
  </div>
</ConfirmDialog>

{#snippet stepRail(current)}
  <ol class="rail" aria-label="Setup progress">
    {#each STEPS as railStep, i (railStep.key)}
      <li
        class="rail-step"
        class:rail-step--current={i === current}
        class:rail-step--done={i < current}
        aria-current={i === current ? 'step' : undefined}
      >
        <span class="rail-dot">{#if i < current}&check;{:else}{i + 1}{/if}</span>
        <span class="rail-label">{railStep.label}</span>
      </li>
    {/each}
  </ol>
{/snippet}

<style>
  .identity-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
    max-width: 640px;
  }

  .page-top {
    display: flex;
    align-items: center;
  }
  .back-link {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    background: none;
    border: none;
    color: var(--muted);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 500;
    cursor: pointer;
    padding: var(--sp-1) 0;
    transition: color var(--duration-fast) var(--ease);
  }
  .back-link:hover {
    color: var(--fg);
  }

  /* One step at a time; each entry eases in so the change reads as a beat. */
  .identity-step {
    display: flex;
    flex-direction: column;
    outline: none;
    animation: step-in 220ms var(--ease) both;
  }
  .identity-step:focus-visible {
    outline: none;
  }
  @keyframes step-in {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .stack {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .step-heading {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--fg);
  }
  .body-text {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .muted-text {
    max-width: 440px;
    margin: 0 auto;
  }
  .mono-inline {
    font-family: var(--mono);
    color: var(--fg);
  }

  /* ── Step rail ──────────────────────────────── */
  .rail {
    list-style: none;
    display: flex;
    margin: 0;
    padding: 0;
    gap: var(--sp-1);
  }
  .rail-step {
    flex: 1;
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding-top: var(--sp-1);
    border-top: 2px solid var(--border);
    font-size: var(--text-xs);
    color: var(--muted);
    transition: color var(--duration-normal) var(--ease),
                border-color var(--duration-normal) var(--ease);
  }
  .rail-step--current {
    border-top-color: var(--accent);
    color: var(--fg);
    font-weight: 600;
  }
  .rail-step--done {
    border-top-color: var(--accent);
    color: var(--muted);
  }
  .rail-dot {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 4px;
    border-radius: 50%;
    background: var(--bg-hover);
    border: 1px solid var(--border);
    font-size: 10px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .rail-step--current .rail-dot {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--fg);
  }
  .rail-step--done .rail-dot {
    background: var(--accent-dim);
    border-color: var(--accent);
    color: var(--accent);
  }
  .rail-label {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* ── Intro tiles ────────────────────────────── */
  .choice-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--sp-3);
  }
  .tile {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--sp-2);
    padding: var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    font: inherit;
    text-align: left;
    cursor: pointer;
    transition: border-color var(--duration-normal) var(--ease),
                background var(--duration-normal) var(--ease),
                transform var(--duration-normal) var(--ease);
  }
  .tile:hover {
    border-color: var(--accent);
    background: var(--bg-hover);
    transform: translateY(-1px);
  }
  .tile-icon {
    display: flex;
    color: var(--accent);
  }
  .tile-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .tile-desc {
    font-size: var(--text-xs);
    color: var(--muted);
    line-height: var(--leading-normal);
  }

  .primer {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
  .primer-row {
    display: flex;
    gap: var(--sp-3);
    align-items: flex-start;
  }
  .primer-row p {
    font-size: var(--text-xs);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .primer-row strong {
    color: var(--fg);
    font-weight: 600;
  }
  .primer-num {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: var(--accent-dim);
    color: var(--accent);
    font-size: var(--text-xs);
    font-weight: 700;
  }

  /* ── Confirm words ──────────────────────────── */
  .confirm-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--sp-3);
  }
  .confirm-field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
  .confirm-input-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }
  .confirm-mark {
    position: absolute;
    right: var(--sp-2);
    display: flex;
    pointer-events: none;
  }
  .confirm-mark--ok {
    color: var(--ok);
    animation: mark-pop 180ms var(--ease) both;
  }
  @keyframes mark-pop {
    from { transform: scale(0.6); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
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
    box-shadow: 0 0 0 2px var(--accent-dim);
  }
  .field-input::placeholder {
    color: var(--muted);
    opacity: 0.6;
  }
  .field-input:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .field-input--textarea {
    resize: vertical;
    min-height: 76px;
    line-height: var(--leading-normal);
    word-break: break-word;
  }
  .field-input--bad {
    border-color: var(--danger);
  }
  .field-input--bad:focus {
    box-shadow: 0 0 0 2px var(--danger-dim);
  }
  .field-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
    min-height: 18px;
  }
  .field-ok {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    color: var(--ok);
    font-weight: 600;
  }
  .field-error {
    font-size: var(--text-sm);
    color: var(--danger);
    line-height: var(--leading-normal);
  }
  .field-help {
    line-height: var(--leading-normal);
    margin-top: var(--sp-1);
  }

  .preview-panel {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-4);
    background: var(--bg);
    border: 1px dashed var(--border);
    border-radius: var(--radius-lg);
  }

  /* ── Warn box (matches Settings) ────────────── */
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

  /* ── Checkbox ───────────────────────────────── */
  .check-row {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
    font-size: var(--text-sm);
    color: var(--fg);
    line-height: var(--leading-normal);
    cursor: pointer;
  }
  .check-row input {
    margin-top: 3px;
    accent-color: var(--accent);
    width: 16px;
    height: 16px;
    flex-shrink: 0;
    cursor: pointer;
  }

  /* ── Done hero ──────────────────────────────── */
  .done-hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: var(--sp-2);
  }
  .done-icon {
    color: var(--ok);
    display: flex;
    animation: mark-pop 260ms var(--ease) both;
  }

  /* ── Manage rows ────────────────────────────── */
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

  /* ── Rotate (manage → rotate-form) ──────────── */
  /* The account-level action gets its own framed block: danger-tinted the
     same way Settings frames its destructive identity actions. */
  .rotate-block {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
    padding: var(--sp-4);
    background: var(--bg);
    border: 1px solid color-mix(in srgb, var(--danger) 30%, var(--border));
    border-radius: var(--radius-lg);
  }
  .rotate-head {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-3);
  }
  .rotate-icon {
    display: flex;
    flex-shrink: 0;
    color: var(--danger);
    margin-top: 1px;
  }
  .rotate-head-text {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }
  .rotate-heading {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
  }
  .rotate-desc {
    line-height: var(--leading-normal);
  }
  .rotate-block .btn {
    align-self: flex-start;
  }

  /* Success note left behind on the manage step after a rotation. */
  .rotate-done {
    padding: var(--sp-2) var(--sp-3);
    background: var(--ok-dim);
    border: 1px solid color-mix(in srgb, var(--ok) 30%, transparent);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    color: var(--ok);
    line-height: var(--leading-normal);
  }

  /* ── Rotate: where the new phrase comes from ── */
  .source-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--sp-3);
  }
  .source-tile {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--sp-1);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    font: inherit;
    text-align: left;
    cursor: pointer;
    transition: border-color var(--duration-normal) var(--ease),
                background var(--duration-normal) var(--ease);
  }
  .source-tile:hover:not(:disabled) {
    border-color: var(--accent);
    background: var(--bg-hover);
  }
  .source-tile:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .source-tile--on,
  .source-tile--on:hover:not(:disabled) {
    border-color: var(--accent);
    background: var(--bg-hover);
  }
  .source-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--fg);
    padding-right: var(--sp-6);
  }
  .source-desc {
    font-size: var(--text-xs);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .source-check {
    position: absolute;
    top: var(--sp-3);
    right: var(--sp-3);
    display: flex;
    color: var(--accent);
    animation: mark-pop 180ms var(--ease) both;
  }

  /* Home for the generated phrase: focus target + label + controls. */
  .rotate-generated {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    outline: none;
  }

  /* ── Rotate confirm: the address that changes ─ */
  .rotate-diff {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-3);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .diff-part {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .diff-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .diff-part--next .diff-label {
    color: var(--accent);
  }
  .diff-value {
    font-family: var(--mono);
    font-size: var(--text-xs);
    color: var(--fg);
    letter-spacing: 0.03em;
    overflow-wrap: anywhere;
  }
  .diff-arrow {
    display: flex;
    justify-content: center;
    color: var(--muted);
  }

  /* ── Actions ────────────────────────────────── */
  .actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3);
    flex-wrap: wrap;
  }
  .actions--end {
    justify-content: flex-end;
  }

  .btn {
    padding: var(--sp-2) var(--sp-4);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease),
                color var(--duration-fast) var(--ease),
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
  .btn--ghost {
    background: transparent;
    color: var(--fg);
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

  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    font: inherit;
    font-size: var(--text-sm);
    font-weight: 600;
    cursor: pointer;
    padding: 0;
    text-align: left;
    text-decoration: underline;
    align-self: flex-start;
  }
  .link-btn:hover {
    color: var(--accent-hover);
  }

  .hint {
    text-align: right;
    margin-top: calc(var(--sp-3) * -1);
  }

  .generating {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-6);
    justify-content: center;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }
  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--fg);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .text-sm { font-size: var(--text-sm); }
  .text-xs { font-size: var(--text-xs); }
  .muted { color: var(--muted); }

  /* ── Responsive ─────────────────────────────── */
  @media (max-width: 560px) {
    .choice-grid,
    .source-grid,
    .confirm-grid {
      grid-template-columns: 1fr;
    }
    .actions {
      flex-direction: column-reverse;
      align-items: stretch;
    }
    .actions .btn {
      width: 100%;
      text-align: center;
    }
    .hint {
      text-align: center;
      margin-top: 0;
    }
    .setting-row {
      flex-direction: column;
      align-items: flex-start;
      gap: var(--sp-1);
    }
  }
</style>
