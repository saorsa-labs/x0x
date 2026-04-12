#!/usr/bin/env node

const [, , mode, ...args] = process.argv;

function usage() {
  console.error(`usage:
  ws_probe.mjs pubsub <base_url> <token> <topic> <message>
  ws_probe.mjs receive-pubsub <base_url> <token> <topic> <timeout_ms>
  ws_probe.mjs direct-receive <base_url> <token> <timeout_ms>
  ws_probe.mjs send-direct <base_url> <token> <agent_id> <message>
  ws_probe.mjs hold <path> <base_url> <token> <hold_ms>`);
  process.exit(2);
}

if (!mode) usage();

function toWsUrl(baseUrl, path, token) {
  const u = new URL(baseUrl);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = path;
  u.search = `token=${encodeURIComponent(token)}`;
  return u.toString();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForOpen(ws, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('websocket open timeout')), timeoutMs);
    ws.addEventListener('open', () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    ws.addEventListener('error', (ev) => {
      clearTimeout(timer);
      reject(new Error(`websocket error: ${ev?.message || 'unknown'}`));
    }, { once: true });
  });
}

function recvJson(ws, timeoutMs = 5000, predicate = () => true) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => cleanup(new Error('websocket receive timeout')), timeoutMs);

    function onMessage(ev) {
      try {
        const frame = JSON.parse(String(ev.data));
        if (!predicate(frame)) return;
        cleanup(null, frame);
      } catch (err) {
        cleanup(new Error(`invalid websocket json: ${err.message}`));
      }
    }

    function onClose() {
      cleanup(new Error('websocket closed before expected frame'));
    }

    function cleanup(err, frame) {
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
      if (err) reject(err);
      else resolve(frame);
    }

    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose, { once: true });
  });
}

function b64(s) {
  return Buffer.from(s, 'utf8').toString('base64');
}

async function connect(path, baseUrl, token) {
  const ws = new WebSocket(toWsUrl(baseUrl, path, token));
  await waitForOpen(ws, 7000);
  const connected = await recvJson(ws, 7000, (frame) => frame?.type === 'connected');
  return { ws, connected };
}

async function run() {
  if (mode === 'pubsub') {
    if (args.length !== 4) usage();
    const [baseUrl, token, topic, message] = args;
    const { ws, connected } = await connect('/ws', baseUrl, token);

    ws.send(JSON.stringify({ type: 'ping' }));
    const pong = await recvJson(ws, 5000, (frame) => frame?.type === 'pong');

    ws.send(JSON.stringify({ type: 'subscribe', topics: [topic] }));
    const subscribed = await recvJson(ws, 5000, (frame) => frame?.type === 'subscribed');

    ws.send(JSON.stringify({ type: 'publish', topic, payload: b64(message) }));
    const received = await recvJson(
      ws,
      8000,
      (frame) => frame?.type === 'message' && frame?.topic === topic && frame?.payload === b64(message),
    );

    ws.close();
    console.log(JSON.stringify({ ok: true, mode, connected, pong, subscribed, received }));
    return;
  }

  if (mode === 'receive-pubsub') {
    if (args.length !== 4) usage();
    const [baseUrl, token, topic, timeoutMsRaw] = args;
    const timeoutMs = Number(timeoutMsRaw);
    const { ws, connected } = await connect('/ws', baseUrl, token);
    ws.send(JSON.stringify({ type: 'subscribe', topics: [topic] }));
    const subscribed = await recvJson(ws, 5000, (frame) => frame?.type === 'subscribed');
    const received = await recvJson(
      ws,
      timeoutMs,
      (frame) => frame?.type === 'message' && frame?.topic === topic,
    );
    ws.close();
    console.log(JSON.stringify({ ok: true, mode, connected, subscribed, received }));
    return;
  }

  if (mode === 'direct-receive') {
    if (args.length !== 3) usage();
    const [baseUrl, token, timeoutMsRaw] = args;
    const timeoutMs = Number(timeoutMsRaw);
    const { ws, connected } = await connect('/ws/direct', baseUrl, token);
    const received = await recvJson(ws, timeoutMs, (frame) => frame?.type === 'direct_message');
    ws.close();
    console.log(JSON.stringify({ ok: true, mode, connected, received }));
    return;
  }

  if (mode === 'send-direct') {
    if (args.length !== 4) usage();
    const [baseUrl, token, agentId, message] = args;
    const { ws, connected } = await connect('/ws', baseUrl, token);
    ws.send(JSON.stringify({ type: 'send_direct', agent_id: agentId, payload: b64(message) }));

    // Success is indicated by the connection staying healthy long enough to receive a pong.
    ws.send(JSON.stringify({ type: 'ping' }));
    const pong = await recvJson(ws, 4000, (frame) => frame?.type === 'pong' || frame?.type === 'error');
    if (pong?.type === 'error') {
      throw new Error(`send_direct error: ${pong.message || JSON.stringify(pong)}`);
    }

    ws.close();
    console.log(JSON.stringify({ ok: true, mode, connected, pong }));
    return;
  }

  if (mode === 'hold') {
    if (args.length !== 4) usage();
    const [path, baseUrl, token, holdMsRaw] = args;
    const holdMs = Number(holdMsRaw);
    const { ws, connected } = await connect(path, baseUrl, token);
    console.log(JSON.stringify({ ok: true, mode, connected }));
    await sleep(holdMs);
    ws.close();
    return;
  }

  usage();
}

run().catch((err) => {
  console.error(JSON.stringify({ ok: false, mode, error: String(err?.message || err) }));
  process.exit(1);
});
