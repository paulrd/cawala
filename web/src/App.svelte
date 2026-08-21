<script>
  import { onMount } from 'svelte';
  import init, { ClientNode } from './wasm/cawala_client.js';

  // status: 'booting' | 'ready' | 'error'
  let status = $state('booting');
  let node = $state(null);
  let endpointId = $state('');
  let targetId = $state('');
  let message = $state('hello from cawala');
  let sending = $state(false);
  let logs = $state([]);

  function addLog(line, cls = '') {
    logs = [
      ...logs,
      { time: new Date().toISOString().substring(11, 22), line, cls },
    ];
    // keep the newest entry visible
    requestAnimationFrame(() => {
      const el = document.querySelector('.log-list');
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  onMount(async () => {
    try {
      addLog('initializing wasm module …');
      await init();
      addLog('wasm module initialized');

      addLog('spawning iroh endpoint …');
      node = await ClientNode.spawn();
      endpointId = node.endpoint_id();
      status = 'ready';
      addLog(`endpoint spawned, our EndpointId: ${endpointId}`);
      addLog('waiting for a target to ping …');
    } catch (err) {
      status = 'error';
      addLog(`startup failed: ${err}`, 'error');
    }
  });

  async function onSend(e) {
    e.preventDefault();
    const target = targetId.trim();
    if (sending || !node || !target) return;

    sending = true;
    const payloadBytes = new TextEncoder().encode(message).length;
    const start = performance.now();
    addLog(`connecting to ${target} …`);
    try {
      const pong = await node.ping(target, message);
      const ms = Math.round(performance.now() - start);
      addLog(
        `connected, sent ${payloadBytes} bytes, response received: "${pong}" (${ms} ms round-trip)`,
        'ok',
      );
    } catch (err) {
      const ms = Math.round(performance.now() - start);
      addLog(`ping failed after ${ms} ms: ${err}`, 'error');
    } finally {
      sending = false;
    }
  }

  async function copyEndpointId() {
    if (!endpointId) return;
    try {
      await navigator.clipboard.writeText(endpointId);
      addLog('EndpointId copied to clipboard');
    } catch (err) {
      addLog(`copy failed: ${err}`, 'error');
    }
  }
</script>

<main>
  <h1>Cawala — M0 debug harness</h1>
  <p class="tagline">
    Browser wasm client (iroh over the N0 public relay) pinging Rust nodes.
    Send a ping, get the payload echoed back.
  </p>

  <section class="card" class:card--error={status === 'error'}>
    <h2>Our EndpointId</h2>
    {#if status === 'booting'}
      <p class="muted">starting iroh endpoint …</p>
    {:else if status === 'error'}
      <p class="muted">endpoint failed to start — see the log below.</p>
    {:else}
      <div class="endpoint-row">
        <code class="endpoint-id">{endpointId}</code>
        <button type="button" onclick={copyEndpointId}>copy</button>
      </div>
    {/if}
  </section>

  <section class="card">
    <h2>Send a ping</h2>
    <form onsubmit={onSend}>
      <label for="target">target EndpointId</label>
      <input
        id="target"
        bind:value={targetId}
        placeholder="e.g. z6Mk… (from the node binary)"
        autocomplete="off"
      />
      <label for="message">message</label>
      <input id="message" bind:value={message} autocomplete="off" />
      <button type="submit" disabled={sending || status !== 'ready'}>
        {sending ? 'ping in flight …' : 'Send ping'}
      </button>
    </form>
    <p class="hint">
      To get a peer EndpointId, run the Rust node from the repo root:
      <code>cargo run -p cawala-node</code> — paste its printed EndpointId
      above and send a ping.
    </p>
  </section>

  <section class="card">
    <h2>Log</h2>
    <div class="log-list">
      {#each logs as log (log)}
        <div class="log-line {log.cls}">
          <span class="time">{log.time}</span>
          <span class="msg">{log.line}</span>
        </div>
      {:else}
        <p class="muted">no events yet</p>
      {/each}
    </div>
  </section>
</main>

<style>
  .endpoint-row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .endpoint-id {
    font-family: var(--mono);
    font-size: 0.85rem;
    word-break: break-all;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  input {
    font: inherit;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  button {
    font: inherit;
    font-weight: 600;
    padding: 8px 14px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--fg);
    color: var(--bg);
    cursor: pointer;
    align-self: flex-start;
  }
  button:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }
  .log-list {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    max-height: 280px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 0.78rem;
    line-height: 1.5;
  }
  .log-line .time {
    color: var(--muted);
    margin-right: 8px;
  }
  .log-line.ok .msg {
    color: var(--ok);
  }
  .log-line.error .msg {
    color: var(--error);
  }
  .muted {
    color: var(--muted);
  }
  .hint {
    color: var(--muted);
    font-size: 0.85rem;
  }
  .hint code {
    font-family: var(--mono);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 5px;
  }
</style>
