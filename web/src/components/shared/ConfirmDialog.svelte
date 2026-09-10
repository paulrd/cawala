<script>
  import { tick } from 'svelte';

  /**
   * ConfirmDialog — modal confirmation for privileged actions.
   * Focus-trapped, Escape/cancel, returns focus to trigger.
   *
   * @param {boolean} open
   * @param {string} title
   * @param {string} message
   * @param {string} [confirmLabel='Confirm']
   * @param {string} [cancelLabel='Cancel']
   * @param {string} [variant='default'] - 'default' | 'danger'
   * @param {function} onConfirm
   * @param {function} onCancel
   */
  let {
    open = false,
    title = 'Confirm',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    variant = 'default',
    onConfirm,
    onCancel,
  } = $props();

  let dialogEl = $state(null);
  let previousFocus = $state(null);

  // Focus trap + restore
  $effect(() => {
    if (open) {
      previousFocus = document.activeElement;
      tick().then(() => {
        if (dialogEl) {
          const first = dialogEl.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
          if (first) first.focus();
        }
      });
    } else if (previousFocus) {
      previousFocus.focus();
      previousFocus = null;
    }
  });

  function handleKeydown(e) {
    if (!open) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      onCancel?.();
      return;
    }
    // Tab trap
    if (e.key === 'Tab' && dialogEl) {
      const focusable = dialogEl.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function handleBackdropClick(e) {
    if (e.target === e.currentTarget) {
      onCancel?.();
    }
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="backdrop" onclick={handleBackdropClick}>
    <div
      class="dialog"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirm-title"
      aria-describedby="confirm-message"
      bind:this={dialogEl}
    >
      <h3 id="confirm-title" class="dialog-title">{title}</h3>
      <p id="confirm-message" class="dialog-message">{message}</p>
      <div class="dialog-actions">
        <button type="button" class="btn btn--ghost" onclick={onCancel}>
          {cancelLabel}
        </button>
        <button
          type="button"
          class="btn"
          class:btn--danger={variant === 'danger'}
          class:btn--primary={variant !== 'danger'}
          onclick={onConfirm}
        >
          {confirmLabel}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(2px);
    padding: var(--sp-4);
  }
  .dialog {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    width: 100%;
    max-width: 420px;
    padding: var(--sp-6);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }
  .dialog-title {
    font-size: var(--text-lg);
    font-weight: 600;
  }
  .dialog-message {
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: var(--leading-normal);
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-3);
    margin-top: var(--sp-2);
  }
  .btn {
    padding: var(--sp-2) var(--sp-4);
    border: none;
    border-radius: var(--radius-md);
    font: inherit;
    font-weight: 600;
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease);
  }
  .btn--primary {
    background: var(--accent);
    color: var(--fg);
  }
  .btn--primary:hover {
    background: var(--accent-hover);
  }
  .btn--danger {
    background: var(--danger);
    color: var(--fg);
  }
  .btn--danger:hover {
    opacity: 0.9;
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
</style>
