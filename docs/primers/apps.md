**Build local apps on top of `x0xd`.**

> Status: current upstream `x0x v0.15.3` is a good localhost app substrate. It is not yet a complete app packaging, discovery, or distribution platform.

x0x is strong when your app runs on the same machine as the daemon and uses its local REST/WebSocket surface.

## Setup once

Install x0x from the current upstream release or `SKILL.md` flow in the repo: [github.com/saorsa-labs/x0x](https://github.com/saorsa-labs/x0x). Then start the daemon with `x0x start` or `x0xd`.

```bash
# macOS
DATA_DIR="$HOME/Library/Application Support/x0x"

# Linux
# DATA_DIR="$HOME/.local/share/x0x"

API=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")
```

If you are building a browser app, serve it from `http://127.0.0.1` or `http://localhost`. Do not assume `file://` is enough. Current daemon auth and CORS behavior make localhost serving the practical path.

## What a local x0x app can do today

A local app can talk to the daemon for:
- identity and runtime status
- contacts, trust, and machine pinning
- gossip publish/subscribe
- direct messaging
- named groups and MLS helpers
- task lists and stores
- transfer records and transfer approval

Avoid hardcoding `127.0.0.1:12700`. Use `api.port` and `api-token` from the data directory.

## Minimal browser example

```html
<!doctype html>
<html lang="en">
  <body>
    <pre id="out">loading...</pre>
    <script>
      const apiBase = "<inject-api-from-api.port>";
      const token = "<inject-token-here>";

      fetch(`${apiBase}/status`, {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then((r) => r.json())
        .then((data) => {
          document.getElementById("out").textContent = JSON.stringify(data, null, 2);
        })
        .catch((err) => {
          document.getElementById("out").textContent = err.message;
        });
    </script>
  </body>
</html>
```

For real-time features:

```javascript
const ws = new WebSocket(`ws://127.0.0.1:12700/ws?token=${TOKEN}`);

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "subscribe",
    topics: ["my-app.events"]
  }));
};

ws.onmessage = (event) => {
  console.log(JSON.parse(event.data));
};
```

## Practical build model today

The most reliable model is:
1. run `x0xd` locally
2. read `api.port` and `api-token`
3. inject those into a local app or local launcher
4. serve the app from localhost if it runs in a browser

This works well for:
- dashboards
- operator consoles
- local chat/coordination tools
- wrappers around contacts, groups, tasks, or messaging

## What not to assume

- Do not assume any arbitrary HTML file opened with `file://` is a working x0x app.
- Do not assume the repo's example apps are perfectly aligned with the current auth and CORS model.
- Do not assume x0x already gives you an app registry, app permissions, or a turnkey packaging story.

## Current limits

- No first-class app registry in the shipped daemon surface.
- No per-app permission model; an app with the token can call the daemon API.
- No standardized packaging/distribution format for apps.
- No turnkey browser-token bootstrap story beyond your own local launcher/server logic.

## References

- [Local apps guide](https://github.com/saorsa-labs/x0x/blob/main/docs/local-apps.md)
- [API reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md)
- [Usage patterns](https://github.com/saorsa-labs/x0x/blob/main/docs/patterns.md)
- [Source](https://github.com/saorsa-labs/x0x)
