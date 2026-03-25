# x0x Example Apps

Single-file web applications that talk to x0xd's REST API. Open any `.html` file in your browser while x0xd is running.

## Quick Start

```bash
# 1. Start the daemon
x0x start

# 2. Open any app in your browser
open examples/apps/x0x-chat.html      # macOS
xdg-open examples/apps/x0x-chat.html  # Linux
```

The apps connect to `http://localhost:12700` by default. If x0xd is running on a different port, edit the `API_URL` constant at the top of each file.

## Apps

| App | Description | x0x features used |
|-----|-------------|-------------------|
| **x0x-chat** | Group chat between agents | WebSocket pub/sub, identity, MLS encryption |
| **x0x-board** | Collaborative kanban board | CRDT task lists, real-time sync |
| **x0x-network** | Network topology dashboard | Discovery, peers, NAT status |
| **x0x-drop** | Secure file sharing | File transfer, trust, identity |
| **x0x-swarm** | AI agent task delegation | Pub/sub, CRDTs, direct messaging |

## How They Work

Each app is a self-contained HTML file with embedded CSS and JavaScript. No build step, no dependencies, no framework. They communicate with x0xd via:

- **REST API** (`http://localhost:12700/...`) for commands
- **WebSocket** (`ws://localhost:12700/ws`) for real-time events
- **SSE** (`http://localhost:12700/events`) as fallback

CORS is enabled by default in x0xd, so browser-based apps can access the API directly.

## Building Your Own

Any web page can be an x0x app. The minimum viable app:

```html
<!DOCTYPE html>
<script>
  const ws = new WebSocket("ws://localhost:12700/ws");
  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "subscribe", topics: ["my-topic"] }));
  };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "message") {
      const payload = atob(msg.payload);
      document.body.innerText += payload + "\n";
    }
  };
</script>
```

See the [API reference](../../docs/api-reference.md) for all available endpoints.
