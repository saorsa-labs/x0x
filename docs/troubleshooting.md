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
curl -sfL https://x0x.md | sh
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
# Verify outbound UDP/5483 is allowed from this machine.
# Exact bootstrap peer IPs may change across releases, so prefer checking
# local network policy/firewall first rather than relying on fixed hostnames.
nc -zuv 142.93.199.50 5483
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
# If UDP egress is blocked, run on a network that allows outbound UDP/5483
# (verify after network change)
curl -sS http://127.0.0.1:12700/health
```

## 3) Messages are not arriving [working]

Symptom:

- Publish returns `{"ok":true}` but no `message` event appears on SSE.

Check:

```bash
# Terminal 1: confirm SSE stream is connected
TOKEN=$(cat ~/Library/Application\ Support/x0x/api-token)  # macOS
curl -N -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12700/events
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
ls -la ~/.x0x
```

```bash
test -f ~/.x0x/agent.key && echo "identity_present" || echo "identity_missing"
```

Fix:

```bash
# If ~/.x0x/agent.key or ~/.x0x/machine.key was deleted, the old identity
# cannot be restored from local disk alone. Keep the new identity and continue.
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

## 6) A space's Wiki or Web tab says pages are unavailable [working]

**Symptom.** You open the **Wiki** or **Web** tab of a private space and instead
of your pages you see a message such as *"Private pages are not available in
this space yet"*, followed by the reason the daemon gave.

**Why.** Pages in a private space have to live in storage that only that
space's members can reach. If the daemon cannot open that storage for the
space — because the space uses a kind of encryption this storage does not
support yet, because you are not an active member, or because the space is
still loading — the tab tells you and shows nothing.

It deliberately does **not** fall back to ordinary storage. Ordinary storage is
readable by anyone who has it and is handed out to your direct contacts
regardless of who is in the space, so putting private pages there would be
worse than showing nothing.

**What to do.**

- Read the reason shown after the message; it comes straight from the daemon.
  *"not a member"* means your membership of that space is not active.
- If it says the space's encryption is not supported yet, private pages for
  that kind of space are **not built yet**. This is tracked as issue #565 and
  is being worked on. There is no setting that turns it on.
- Public spaces are unaffected. Switching a space to public is **not** a
  workaround: it makes the pages readable by anyone.

**Pages you saved with an earlier version.** They are still on disk, exactly
where the older version put them, and nothing has been moved, copied,
republished or deleted. They are simply no longer shown in a private space's
tab, because that older location is not private. If you need one of them back,
ask before the next release rather than re-saving it into a private space.

### Who can edit pages

- **Private space, where private pages work.** Pages are stored with the
  space's members, and **any active member can save** — the daemon accepts a
  write from any current member of the group.
- **Private space using an encryption this storage does not support yet.** The
  tab says pages are unavailable. That is the case tracked by issue #565.
- **Public space.** This version has **not** been fixed yet. It still keeps
  pages in a store held by **your own device**, not one shared with the space.
  Two members of the same public space can each end up with their own copy, so
  what you save may not be what another member sees. Treat public-space pages
  as your own notes until this is fixed. Do not switch a space to public in
  order to share pages — it does not share them, and it makes them readable by
  anyone.
