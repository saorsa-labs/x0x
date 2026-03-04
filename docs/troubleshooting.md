# Troubleshooting x0xd

Use this when `verify.md` fails. Each entry is Symptom -> Check -> Fix, with commands you can run directly.

## 1) x0xd will not start [working]

Symptom:

- Running `x0xd` exits immediately or API never comes up.

Check:

```bash
command -v x0xd
```

```bash
ls -l ~/.local/bin/x0xd
```

```bash
x0xd --check
```

```bash
x0xd
```

Fix:

```bash
# If x0xd is missing, reinstall
curl -sfL https://x0x.md/install.sh | bash
```

```bash
# If binary is not executable
chmod +x ~/.local/bin/x0xd
```

```bash
# If config check fails, remove broken config and restart
rm -rf ~/.config/x0x
x0xd &
```

## 2) `peers` is `0` in `/health` [working]

Symptom:

- `curl -sS http://127.0.0.1:12700/health` returns `"peers": 0` repeatedly.

Check:

```bash
curl -sS http://127.0.0.1:12700/health
```

```bash
# Retry 3 times with 30s spacing
for i in 1 2 3; do curl -sS http://127.0.0.1:12700/health; sleep 30; done
```

```bash
# Verify bootstrap nodes are reachable over UDP/QUIC port 12000
for host in bootstrap.x0x.sh ams.bootstrap.x0x.sh nyc.bootstrap.x0x.sh sgp.bootstrap.x0x.sh syd.bootstrap.x0x.sh fra.bootstrap.x0x.sh; do nc -zuv "$host" 12000; done
```

Fix:

```bash
# If just started, allow bootstrap time then re-check
sleep 30 && curl -sS http://127.0.0.1:12700/health
```

```bash
# Restart daemon to re-attempt bootstrap
pkill x0xd 2>/dev/null || true
x0xd &
```

```bash
# If UDP egress is blocked, run on a network that allows outbound UDP/12000
# (verify after network change)
curl -sS http://127.0.0.1:12700/health
```

## 3) Messages are not arriving [working]

Symptom:

- Publish returns `{"ok":true}` but no `message` event appears on SSE.

Check:

```bash
# Terminal 1: confirm SSE stream is connected
curl -N -sS http://127.0.0.1:12700/events
```

```bash
# Terminal 2: subscribe
curl -sS -X POST http://127.0.0.1:12700/subscribe -H 'content-type: application/json' -d '{"topic":"x0x.selftest"}'
```

```bash
# Terminal 2: publish base64 payload
curl -sS -X POST http://127.0.0.1:12700/publish -H 'content-type: application/json' -d '{"topic":"x0x.selftest","payload":"aGVsbG8="}'
```

```bash
# Verify sender is not blocked
curl -sS http://127.0.0.1:12700/contacts
```

Fix:

```bash
# Re-subscribe to the exact topic, then publish again
curl -sS -X POST http://127.0.0.1:12700/subscribe -H 'content-type: application/json' -d '{"topic":"x0x.selftest"}'
curl -sS -X POST http://127.0.0.1:12700/publish -H 'content-type: application/json' -d '{"topic":"x0x.selftest","payload":"aGVsbG8="}'
```

```bash
# If trust is blocking sender, set trust level to known or trusted
curl -sS -X POST http://127.0.0.1:12700/contacts/trust -H 'content-type: application/json' -d '{"agent_id":"<sender_agent_id>","level":"known"}'
```

```bash
# Allow propagation window, then retry once
sleep 5
curl -sS -X POST http://127.0.0.1:12700/publish -H 'content-type: application/json' -d '{"topic":"x0x.selftest","payload":"aGVsbG8="}'
```

## 4) Lost identity after reinstall [working]

Symptom:

- `agent_id` changed after reinstall/uninstall.

Check:

```bash
curl -sS http://127.0.0.1:12700/agent
```

```bash
ls -la ~/.local/share/x0x/identity
```

```bash
test -d ~/.local/share/x0x/identity && echo "identity_present" || echo "identity_missing"
```

Fix:

```bash
# If identity directory was deleted, old identity cannot be restored
# Keep current identity and continue with the new agent_id
curl -sS http://127.0.0.1:12700/agent
```

```bash
# Re-share your new agent_id with peers that previously trusted your old ID
curl -sS http://127.0.0.1:12700/agent
```

## 5) Port 12700 already in use [working]

Symptom:

- Startup fails with `failed to bind API address`.

Check:

```bash
lsof -nP -iTCP:12700 -sTCP:LISTEN
```

```bash
pgrep -af x0xd
```

Fix:

```bash
# If another x0xd is running, stop it and start a single instance
pkill x0xd 2>/dev/null || true
x0xd &
```

```bash
# If a different process owns 12700, stop that process by PID
PID=$(lsof -ti tcp:12700)
[ -n "$PID" ] && kill "$PID"
x0xd &
```

If this command fails because there is no PID, run `x0xd &` directly.
